//
//  URLUtilities.swift
//  Tapestry
//
//  Created by Craig Hockenberry on 3/19/23.
//

import Foundation

import UniformTypeIdentifiers // for MIME types

public enum URLUtilities {

	public static func createPostBody(with parameters: [String:String]) -> Data {
		var first = true
		var bodyParameters = ""
		for (key, value) in parameters {
			if !first {
				bodyParameters += "&"
			}
			bodyParameters += "\(key)=\(value)"
			first = false
		}
		
		let body = bodyParameters.data(using: String.Encoding.utf8, allowLossyConversion: true)
		return body ?? Data()
	}
	
	public static func convertFormField(named name: String, value: String, using boundary: String) -> String {
		var fieldString = "--\(boundary)\r\n"
		fieldString += "Content-Disposition: form-data; name=\"\(name)\"\r\n"
		fieldString += "\r\n"
		fieldString += "\(value)\r\n"
		
		return fieldString
	}
	
	public static func convertFileData(fieldName: String, fileName: String, mimeType: String, fileData: Data, using boundary: String) -> Data {
		var data = Data()
		
		data.appendString("--\(boundary)\r\n")
		data.appendString("Content-Disposition: form-data; name=\"\(fieldName)\"; filename=\"\(fileName)\"\r\n")
		data.appendString("Content-Type: \(mimeType)\r\n\r\n")
		data.append(fileData)
		data.appendString("\r\n")
		
		return data as Data
	}

}

extension Data {
	
	mutating func appendString(_ string: String) {
		if let data = string.data(using: .utf8) {
			self.append(data)
		}
	}
	
}

public extension URL {

	var mimeType: String {
		if let mimeType = UTType(filenameExtension: self.pathExtension)?.preferredMIMEType {
			return mimeType
		}
		else {
			return "application/octet-stream"
		}
	}
		
	var isBrowsable: Bool {
        return ["https", "http"].contains(scheme)
	}

	var rootUrl: URL? {
		if var urlComponents = URLComponents(url: self, resolvingAgainstBaseURL: false) {
			urlComponents.path = ""
			urlComponents.fragment = nil
			urlComponents.query = nil
			
			return urlComponents.url
		}
		return nil
	}
	
	var isRelative: Bool {
		return host() == nil || scheme == nil
	}
	
}
