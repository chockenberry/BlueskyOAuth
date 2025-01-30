//
//  BlueskyAuthorization.swift
//  BlueskyOAuth
//
//  Created by Craig Hockenberry on 1/30/25.
//

// NOTE: I have no idea what I'm doing here: https://github.com/bluesky-social/atproto/discussions/2656#discussioncomment-10596203

import Foundation
import AuthenticationServices

internal class BlueskyAuthorization: NSObject {
	
	var authenticationSession: ASWebAuthenticationSession?
	
	private let appRedirectUri = "boat://oauth"
	private let clientId = "https://furbo.org/stuff/client-metadata.json"

	// MARK: - Authorize
	
	@MainActor // NOTE: ASWebAuthenticationSession uses a window, so it needs to be on the main thread.
	func authorize() async -> (accessToken: String?, refreshToken: String?, error: Error?) {
		// start the OAuth authorization flow
		let result = await withCheckedContinuation({ continuation in
			oauthAuthorize(clientId: clientId) { accessToken, refreshToken, error in
				continuation.resume(returning: (accessToken, refreshToken, error))
			}
		})
		
		return result
	}
	
	// https://atproto.com/specs/oauth#summary-of-authorization-flow
	
	func oauthAuthorize(clientId: String, completionHandler: @escaping BlueskyAuthorization.CompletionHandler) {
		
		let type = "code"
		let scope = "atproto"

		let state = Int(Date.timeIntervalSinceReferenceDate)
		
		let link = "https://bsky.social" // something from PAR?
		
		do {
			let endpoint = "\(link)?client_id=\(clientId)&response_type=\(type)&redirect_uri=\(appRedirectUri)&scope=\(scope)&state=\(state)"
			if let authorizeUrl = URL(string:endpoint) {
				let callbackUrlScheme = URL(string: appRedirectUri)!.scheme
				
				authenticationSession = ASWebAuthenticationSession(url: authorizeUrl, callbackURLScheme: callbackUrlScheme, completionHandler: { callbackUrl, error in
					guard error == nil else {
						print("callbackUrl = \(String(describing: callbackUrl)), error = \(String(describing: error))")
						if let errorCode = (error as? ASWebAuthenticationSessionError)?.code, errorCode == .canceledLogin {
							completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "Cancelled login"))
						}
						else {
							completionHandler(nil, nil, error)
						}
						return
					}
					
					guard let callbackUrl else {
						completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "No callback URL"))
						return
					}
					
					if let urlComponents = NSURLComponents(url: callbackUrl, resolvingAgainstBaseURL: false) {
						if let codeQueryItem = urlComponents.queryItems?.first(where: { $0.name == "code" }) {
							if let code = codeQueryItem.value {
								print("code = \(code)")
								self.oauthGetToken(clientId: clientId, code: code, completionHandler: completionHandler)
							}
						}
						else {
							completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "Access denied"))
						}
					}
				})
				authenticationSession?.presentationContextProvider = self
				authenticationSession?.prefersEphemeralWebBrowserSession = true
				authenticationSession?.start()
			}
			else {
				completionHandler(nil, nil, BlueskyAuthorizationError.configuration(detail: "Invalid authorization URL"))
			}
		}
	}
	
	private func oauthGetToken(clientId: String, code: String, completionHandler: @escaping BlueskyAuthorization.CompletionHandler) {
		
		let link = "something from PAR request?"

		do {
			if let tokenUrl = URL(string: link) {
				Task<Void, Never> {
					var request = URLRequest(url: tokenUrl, cachePolicy: .reloadIgnoringLocalCacheData)
					let parameters = [
						"grant_type": "authorization_code",
						"scope": "atproto",
						"code": code,
						"client_id": clientId,
						"redirect_uri": appRedirectUri,
					]
					
					request.httpMethod = "POST"
					request.httpBody = URLUtilities.createPostBody(with: parameters)
					
					do {
						let (data, response) = try await URLSession.shared.data(for: request)
						if let httpResponse = response as? HTTPURLResponse {
							if httpResponse.statusCode == 200 {
								if let object = try? JSONSerialization.jsonObject(with: data) {
									print("JSON => \(object)")
									if let dictionary = object as? Dictionary<String,Any> {
										let refreshToken = dictionary["refresh_token"] as? String
										if let accessToken = dictionary["access_token"] as? String {
											completionHandler(accessToken, refreshToken, nil)
											return
										}
									}
									completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "Missing OAuth access token"))
								}
								else {
									if let text = String(data: data, encoding: .utf8) {
										print("TEXT => \(text)")
									}
									else {
										print("DATA => \(String(describing: data))")
									}
									completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "No JSON while getting OAuth token"))
								}
							}
							else {
								print("response = \(httpResponse.statusCode) => \(String(describing: response))")
								let detail: String
								if httpResponse.statusCode == 400 || httpResponse.statusCode == 401 {
									detail = "Invalid account information (OAuth code \(httpResponse.statusCode))"
								}
								else {
									detail = "Invalid OAuth response code: \(httpResponse.statusCode)"
								}
								completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: detail))
							}
						}
						else {
							print("OAuth response not HTTP")
							completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "Invalid OAuth response"))
						}
					}
					catch {
						print("OAuth exception = \(error.localizedDescription)")
						completionHandler(nil, nil, error)
					}
				}
			}
			else {
				completionHandler(nil, nil, BlueskyAuthorizationError.configuration(detail: "No OAuth token URL"))
			}
		}
	}
	
	// MARK: - Refresh
	
	func refresh(with refreshToken: String, failStatusCode: Int) async -> (String?, String?, Error?, Bool) {
		let result = await withCheckedContinuation({ continuation in
			oauthRefresh(with: refreshToken, failStatusCode: failStatusCode, clientId: clientId) { accessToken, refreshToken, error, retry in
				continuation.resume(returning: (accessToken, refreshToken, error, retry))
			}
		})
		
		return result
	}
	
	func oauthRefresh(with refreshToken: String, failStatusCode: Int, clientId: String, completionHandler: @escaping BlueskyAuthorization.RefreshCompletionHandler) {

		let link = "something from PAR request?"

		if let tokenUrl = URL(string:"\(link)") {
			Task<Void, Never> {
				var request = URLRequest(url: tokenUrl, cachePolicy: .reloadIgnoringLocalCacheData)
				let parameters = [
					"refresh_token": refreshToken,
					"grant_type": "refresh_token",
					"client_id": clientId,
				]
								
				request.httpMethod = "POST"
				request.httpBody = URLUtilities.createPostBody(with: parameters)
				
				var retry = false
				
				do {
					let (data, response) = try await URLSession.shared.data(for: request)
					if let httpResponse = response as? HTTPURLResponse {
						if httpResponse.statusCode == 200 {
							if let object = try? JSONSerialization.jsonObject(with: data) {
								print("JSON => \(object)")
								if let dictionary = object as? Dictionary<String,Any> {
									let newRefreshToken = dictionary["refresh_token"] as? String
									if let newAccessToken = dictionary["access_token"] as? String {
										completionHandler(newAccessToken, newRefreshToken, nil, retry)
										return
									}
								}
								completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "Missing OAuth access token during refresh"), retry)
							}
							else {
								completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "No JSON while getting OAuth token during refresh"), retry)
							}
						}
						else {
							// got a non-200 response, retry the request
							retry = true
							let (data, response) = try await URLSession.shared.data(for: request)
							if let httpResponse = response as? HTTPURLResponse {
								if httpResponse.statusCode == 200 {
									if let object = try? JSONSerialization.jsonObject(with: data) {
										print("retry JSON => \(object)")
										if let dictionary = object as? Dictionary<String,Any> {
											let newRefreshToken = dictionary["refresh_token"] as? String
											if let newAccessToken = dictionary["access_token"] as? String {
												completionHandler(newAccessToken, newRefreshToken, nil, retry)
												return
											}
										}
										completionHandler(nil, nil, BlueskyAuthorizationError.authentication(detail: "Missing OAuth access token during refresh retry"), retry)
									}
									else {
										completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "No JSON while getting OAuth token during refresh retry"), retry)
									}
								}
								else {
									print("response = \(httpResponse.statusCode) => \(String(describing: response))")
									if httpResponse.statusCode == failStatusCode {
										completionHandler(nil, nil, BlueskyAuthorizationError.authenticationFailure, retry)
									}
									else {
										let detail = "Invalid OAuth response code: \(httpResponse.statusCode)"
										completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: detail), retry)
									}
								}
							}
							else {
								completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "No HTTP response for OAuth during refresh retry"), retry)
							}
						}
					}
					else {
						completionHandler(nil, nil, BlueskyAuthorizationError.server(detail: "No HTTP response for OAuth during refresh"), retry)
					}
				}
				catch {
					print("exception = \(error.localizedDescription)")
					completionHandler(nil, nil, error, retry)
				}
			}
		}
		else {
			completionHandler(nil, nil, BlueskyAuthorizationError.configuration(detail: "No OAuth token URL during refresh"), false)
		}
	}
	
}

enum BlueskyAuthorizationError: Error {
	case unknown
	case configuration(detail: String)
	case authentication(detail: String)
	case authenticationFailure
	case server(detail: String)
}

extension BlueskyAuthorizationError: LocalizedError {
	var errorDescription: String? {
		switch self {
		case .unknown: return "Unknown error"
		case let .configuration(detail): return "Configuration: \(detail)"
		case let .authentication(detail): return "Authorization: \(detail)"
		case .authenticationFailure: return "Authorization failed"
		case let .server(detail): return "Server: \(detail)"
		}
	}
}

extension BlueskyAuthorization {
	
	public typealias CompletionHandler = (_ accessToken: String?, _ refreshToken: String?, _ error: Error?) -> Void

	public typealias RefreshCompletionHandler = (_ accessToken: String?, _ refreshToken: String?, _ error: Error?, _ retry: Bool) -> Void

}

extension BlueskyAuthorization: ASWebAuthenticationPresentationContextProviding {
	
	func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		return ASPresentationAnchor()
	}
	
}
