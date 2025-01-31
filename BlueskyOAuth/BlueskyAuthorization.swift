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
	
	private let appRedirectUri = "org.furbo:/oauth"
	private let clientId = "https://furbo.org/stuff/client-metadata.json"

	// MARK: - Authorize
	
	// https://atproto.com/specs/oauth#summary-of-authorization-flow
	
	// client metadata:
	/*
	 {
	   "client_id": "https://furbo.org/stuff/client-metadata.json",
	   "application_type": "native",
	   "client_name": "BlueskyOAuth iOS App",
	   "client_uri": "https://furbo.org",
	   "dpop_bound_access_tokens": true,
	   "grant_types": [
		 "authorization_code",
		 "refresh_token"
	   ],
	   "redirect_uris": [
		 "boat://oauth"
	   ],
	   "response_types": [
		 "code"
	   ],
	   "scope": "atproto transition:generic",
	   "token_endpoint_auth_method": "none"
	 }
	 */

	@MainActor // NOTE: ASWebAuthenticationSession uses a window, so it needs to be on the main thread.
	func authorize() async -> (accessToken: String?, refreshToken: String?, error: Error?) {
		// get the pushed authorization request (PAR)
		guard let pushedAuthorizationRequestUri = await getPushedAuthorizationRequestUri() else {
			return (nil, nil, BlueskyAuthorizationError.server(detail: "No PAR request URI"))
		}
		
		// start the OAuth authorization flow
		let result = await withCheckedContinuation({ continuation in
			oauthAuthorize(clientId: clientId, requestUri: pushedAuthorizationRequestUri) { accessToken, refreshToken, error in
				continuation.resume(returning: (accessToken, refreshToken, error))
			}
		})
		
		return result
	}
	
	// authorization server metadata: https://bsky.social/.well-known/oauth-authorization-server
	/* relevant fields:
		"issuer" : "https://bsky.social",
		"pushed_authorization_request_endpoint" : "https://bsky.social/oauth/par",
		"authorization_endpoint" : "https://bsky.social/oauth/authorize",
		"token_endpoint" : "https://bsky.social/oauth/token",
		"scopes_supported" : [
			"atproto",
			"transition:generic",
			"transition:chat.bsky"
		],
	 */

	func getPushedAuthorizationRequestUri() async -> String? {
		let link = "https://bsky.social/oauth/par"
		if let url = URL(string: link) {
			let state = String(Int(Date.timeIntervalSinceReferenceDate))

			let codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
			//let codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
			// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
			let codeChallenge = "whatever"
			
			var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
			// parameters per: https://atproto.com/specs/oauth#authorization-requests
			let parameters = [
				"client_id": clientId,
				"response_type": "code",
				"code_challenge": codeChallenge, // clients must generate new, unique, random challenges for every authorization request
				"code_challenge_method": "S256", // the S256 challenge method must be supported by all clients and Authorization Servers
				"state": state,
				"redirect_uri": appRedirectUri,
				"scope": "atproto",
				"login_hint": "aloginhint",
			]
			
			
			request.httpMethod = "POST"
			request.httpBody = URLUtilities.createPostBody(with: parameters)
			
			do {
				let (data, response) = try await URLSession.shared.data(for: request)
				if let httpResponse = response as? HTTPURLResponse {
					if httpResponse.statusCode == 201 {
						if let object = try? JSONSerialization.jsonObject(with: data) {
							print("JSON => \(object)")
							if let dictionary = object as? Dictionary<String,Any> {
								if let requestUri = dictionary["request_uri"] as? String {
									// example: urn:ietf:params:oauth:request_uri:req-7f1d3b2c667257cd9e8d9f0c2b5876ef
									return requestUri
								}
							}
						}
					}
					else {
						if let object = try? JSONSerialization.jsonObject(with: data) {
							/*
							 po object
							 ▿ 2 elements
							   ▿ 0 : 2 elements
								 - key : error
								 - value : invalid_redirect_uri
							   ▿ 1 : 2 elements
								 - key : error_description
								 - value : Invalid redirect URI scheme "boat:"
							 */
							print("\(httpResponse.statusCode): JSON => \(object)")
						}
						else if let body = String(data: data, encoding: .utf8) {
							print("\(httpResponse.statusCode): body = '\(body)'")
						}
					}
				}
			}
			catch {
				print("PAR exception = \(error.localizedDescription)")
			}
		}
		return nil
	}
	
	func oauthAuthorize(clientId: String, requestUri: String, completionHandler: @escaping BlueskyAuthorization.CompletionHandler) {
		
		let type = "code"
		let scope = "atproto"

		let state = Int(Date.timeIntervalSinceReferenceDate)
		
		let link = "https://bsky.social/oauth/authorize" // something from pushedAuthorizationRequestUri?
		
		do {
			//let endpoint = "\(link)?client_id=\(clientId)&response_type=\(type)&redirect_uri=\(appRedirectUri)&scope=\(scope)&state=\(state)"
			let endpoint = "\(link)?request_uri=\(requestUri)"
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
