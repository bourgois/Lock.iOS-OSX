// PasswordlessInteractor.swift
//
// Copyright (c) 2017 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Foundation
import Auth0

struct PasswordlessInteractor: PasswordlessAuthenticatable {

    let authentication: Authentication
    let dispatcher: Dispatcher
    let user: User
    let options: Options
    let emailValidator: InputValidator = EmailValidator()

    var identifier: String? { return self.user.email }

    func start(_ connection: String, callback: @escaping (PasswordlessAuthenticatableError?) -> ()) {
        guard let identifier = self.identifier else { return callback(.nonValidInput) }

        self.authentication.startPasswordless(email: identifier, type: .Code, connection: connection, parameters: self.options.parameters).start {
            guard case .success = $0 else {
                callback(.codeNotSent)
                return self.dispatcher.dispatch(result: .error(PasswordlessAuthenticatableError.codeNotSent))
            }
            //self.dispatcher.dispatch(result: .forgotPassword(identifier))
            callback(nil)
        }
    }

    mutating func updateEmail(_ value: String?) throws {
        self.user.email = value?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let error = self.emailValidator.validate(value)
        self.user.validEmail = error == nil
        if let error = error { throw error }
    }
}
