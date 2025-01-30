//
//  ContentView.swift
//  BlueskyOAuth
//
//  Created by Craig Hockenberry on 1/30/25.
//

import SwiftUI

struct ContentView: View {
	
	@State private var errorTitle = ""
	@State private var errorMessage = ""
	@State private var presentError = false

    var body: some View {
        VStack {
			Button("Authorize Bluesky") {
				Task {
					let blueSkyAuthorization = BlueskyAuthorization()
					let (accessToken, refreshToken, error) = await blueSkyAuthorization.authorize()
					if let error {
						errorTitle = "Authorization Error"
						errorMessage = error.localizedDescription
						presentError = true
					}
					else {
						print("accessToken = \(accessToken ?? "nil"), refreshToken = \(refreshToken ?? "nil")")
					}
				}
			}
			.buttonStyle(.borderedProminent)
        }
        .padding()
		.alert(errorTitle, isPresented: $presentError) {
			Button("OK", role: .cancel) { }
		} message: {
			Text(errorMessage)
		}
    }
}

#Preview {
    ContentView()
}
