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

struct PasswordlessInteractor: PasswordlessAuthenticatable, Loggable {

    let authentication: Authentication
    let dispatcher: Dispatcher
    let user: User
    let options: Options

    let emailValidator: InputValidator = EmailValidator()
    let codeValidator: InputValidator = OneTimePasswordValidator()

    var identifier: String? { return self.user.email }
    var code: String? = nil
    var validCode: Bool = false

    init(authentication: Authentication, dispatcher: Dispatcher, user: User, options: Options) {
        self.authentication = authentication
        self.dispatcher = dispatcher
        self.user = user
        self.options = options
    }

    func request(_ connection: String, callback: @escaping (PasswordlessAuthenticatableError?) -> ()) {
        guard let identifier = self.identifier, self.user.validEmail else { return callback(.nonValidInput) }

        self.authentication.startPasswordless(email: identifier, type: .Code, connection: connection, parameters: self.options.parameters).start {
            guard case .success = $0 else {
                callback(.codeNotSent)
                return self.dispatcher.dispatch(result: .error(PasswordlessAuthenticatableError.codeNotSent))
            }
            //self.dispatcher.dispatch(result: .forgotPassword(identifier))
            callback(nil)
        }
    }

    func login(_ connection: String, callback: @escaping (CredentialAuthError?) -> ()) {
        guard let password = self.code, self.validCode, let identifier = self.identifier, self.user.validEmail  else { return callback(.nonValidInput) }

        let credentialAuth = CredentialAuth(oidc: options.oidcConformant, realm: connection, authentication: authentication)

        credentialAuth
            .request(withIdentifier: identifier, password: password, options: self.options)
            .start { result in
                switch result {
                case .failure(let cause):
                    self.logger.error("Failed login of user <\(self.identifier)> with error \(cause)")
                    callback(.couldNotLogin)
                    self.dispatcher.dispatch(result: .error(CredentialAuthError.couldNotLogin))
                case .success(let credentials):
                    self.logger.info("Authenticated user <\(self.identifier)>")
                    callback(nil)
                    self.dispatcher.dispatch(result: .auth(credentials))
                }
        }

    }

    mutating func update(type: InputField.InputType, value: String?) throws {
        let error: Error?
        switch type {
        case .email:
            error = self.update(email: value)
        case .oneTimePassword:
            error = self.update(code: value)
        default:
            error = InputValidationError.mustNotBeEmpty
        }
        if let error = error { throw error }
    }

    private mutating func update(email: String?) -> Error? {
        self.user.email = email?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let error = self.emailValidator.validate(email)
        self.user.validEmail = error == nil
        return error
    }

    private mutating func update(code: String?) -> Error? {
        self.code = code?.trimmingCharacters(in: CharacterSet.whitespaces)
        let error = self.codeValidator.validate(code)
        self.validCode = error == nil
        return error
    }
}
