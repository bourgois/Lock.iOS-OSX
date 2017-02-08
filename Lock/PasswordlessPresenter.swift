// PasswordlessPresenter.swift
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

class PasswordlessPresenter: Presentable, Loggable {

    var interactor: PasswordlessAuthenticatable
    let connection: PasswordlessConnection
    let navigator: Navigable
    let mode: PasswordlessMode

    init(interactor: PasswordlessAuthenticatable, connection: PasswordlessConnection, navigator: Navigable, mode: PasswordlessMode) {
        self.interactor = interactor
        self.connection = connection
        self.navigator = navigator
        self.mode = mode
    }

    var messagePresenter: MessagePresenter?

    var view: View {
        switch self.mode {
        case .capture:
            return self.showRequestForm()
        case .code:
            return self.showCodeForm()
        default:
            return self.showCodeForm()
        }
    }

    private func showRequestForm() -> View {
        let view = PasswordlessEmailView(withMode: .capture, email: self.interactor.identifier)
        let form = view.form

        view.form?.onValueChange = { input in
            self.messagePresenter?.hideCurrent()
            guard case .email = input.type else { return }
            do {
                try self.interactor.update(type: .email, value: input.text)
                input.showValid()
            } catch {
                input.showError()
            }
        }

        let action = { [weak form] (button: PrimaryButton) in
            self.messagePresenter?.hideCurrent()
            self.logger.info("request passwordless \(self.interactor.identifier)")
            let interactor = self.interactor
            let connection = self.connection
            button.inProgress = true
            interactor.request(connection.name) { error in
                Queue.main.async {
                    button.inProgress = false
                    form?.needsToUpdateState()
                    if let error = error {
                        self.messagePresenter?.showError(error)
                        self.logger.error("Failed with error \(error)")
                    } else {
                        self.navigator.navigate(Route.passwordlessEmail(mode: .code, connection: connection))
                    }
                }
            }
        }

        view.primaryButton?.onPress = action
        view.form?.onReturn = { [unowned view] _ in
            guard let button = view.primaryButton else { return }
            action(button)
        }
        return view
    }

    private func showCodeForm() -> View {
        let view = PasswordlessEmailView(withMode: .code, email: self.interactor.identifier)
        let form = view.form

        view.form?.onValueChange = { input in
            self.messagePresenter?.hideCurrent()
            guard case .oneTimePassword = input.type else { return }
            do {
                try self.interactor.update(type: .oneTimePassword, value: input.text)
                input.showValid()
            } catch {
                input.showError()
            }
        }

        let action = { [weak form] (button: PrimaryButton) in
            self.messagePresenter?.hideCurrent()
            self.logger.info("login passwordless \(self.interactor.identifier)")
            let interactor = self.interactor
            let connection = self.connection
            button.inProgress = true
            interactor.login(connection.name) { error in
                Queue.main.async {
                    button.inProgress = false
                    form?.needsToUpdateState()
                    if let error = error {
                        self.messagePresenter?.showError(error)
                        self.logger.error("Failed with error \(error)")
                    }
                }
            }
        }

        view.primaryButton?.onPress = action
        view.form?.onReturn = { [unowned view] _ in
            guard let button = view.primaryButton else { return }
            action(button)
        }

        view.secondaryButton?.onPress = { button in
            self.navigator.onBack()
        }

        return view
    }
}
