import sys
import json
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QLineEdit, QListWidget, QListWidgetItem, 
    QDialog, QGraphicsOpacityEffect, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtGui import QMovie
from cryptography.fernet import Fernet
import os
import secrets


class PasswordItemWidget(QWidget):
    def __init__(self, entry, parent=None):
        super().__init__(parent)
        self.entry = entry
        self.parent = parent

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        self.site_label = QLabel(entry['site'])  # Display site
        self.site_label.setFixedWidth(200) 
        self.username_label = QLabel(entry['username'])  
        self.username_label.setFixedWidth(200) 

        self.delete_button = QPushButton("Delete")
        self.delete_button.setFixedWidth(100)  
        self.delete_button.clicked.connect(self.delete_item)

        layout.addWidget(self.site_label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.delete_button)
        layout.addStretch()  # Add stretch to push the delete button to the right

        self.setLayout(layout)


    def delete_item(self):
        confirm = QMessageBox.question(self, "Confirm Deletion", "Are you sure you want to delete this password?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            self.parent.delete_password(self.entry)


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.key = None
        self.data_file = 'passwords.json'
        self.init_encryption()
        self.dark_theme_applied = False
        self.initUI()

    def init_encryption(self):
        key_file = 'key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher_suite = Fernet(self.key)

    def encrypt(self, plaintext):
        return self.cipher_suite.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext):
        return self.cipher_suite.decrypt(ciphertext.encode()).decode()

    def load_passwords(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                encrypted_data = f.read()
            if encrypted_data:
                try:
                    decrypted_data = self.decrypt(encrypted_data)
                    return json.loads(decrypted_data)
                except:
                    return []
        return []

    def save_passwords(self, passwords):
        encrypted_data = self.encrypt(json.dumps(passwords))
        with open(self.data_file, 'w') as f:
            f.write(encrypted_data)

    def initUI(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)
        
        self.header = QHBoxLayout()
        self.title = QLabel("Password Manager")
        self.title.setFont(QFont('Arial', 20))

        self.theme_button = QPushButton("Switch Theme")
        self.theme_button.setFixedWidth(100)  # Set fixed width for consistency

        self.add_button = QPushButton("Add New Password")
        self.add_button.setFixedWidth(100)

        self.theme_button.clicked.connect(self.switch_theme)
        self.add_button.clicked.connect(self.show_add_password_popup)

        self.header.addWidget(self.title)
        self.header.addStretch()  # Add stretch to push buttons to the right
        self.header.addWidget(self.theme_button)
        self.header.addWidget(self.add_button)

        self.password_list = QListWidget()
        self.password_list.itemDoubleClicked.connect(self.edit_password)
        
        self.layout.addLayout(self.header)
        self.layout.addWidget(self.password_list)

        self.load_password_list()

    def load_password_list(self):
        self.password_list.clear()
        passwords = self.load_passwords()
        for entry in passwords:
            item_widget = PasswordItemWidget(entry, self)
            item = QListWidgetItem(self.password_list)
            item.setSizeHint(item_widget.sizeHint())
            item.setData(Qt.ItemDataRole.UserRole, entry)  # Ensure the entry is set as item data
            self.password_list.addItem(item)
            self.password_list.setItemWidget(item, item_widget)


    def delete_password(self, entry):
        passwords = self.load_passwords()
        passwords = [pw for pw in passwords if pw != entry]
        self.save_passwords(passwords)
        self.load_password_list()

    def show_add_password_popup(self):
        self.blur_window(True)
        self.popup = AddPasswordPopup(self)
        self.popup.exec()
        self.blur_window(False)
        self.load_password_list()

    def edit_password(self, item):
        self.blur_window(True)
        entry = item.data(Qt.ItemDataRole.UserRole)
        if entry is not None:
            self.popup = EditPasswordPopup(self, entry)  # Pass the entry directly
            self.popup.exec()
        self.blur_window(False)
        self.load_password_list()


    def switch_theme(self):
        if not self.dark_theme_applied:
            # Apply dark theme
            self.setStyleSheet("QWidget { background-color: #2e2e2e; color: #ffffff; } QPushButton { background-color: #3a3a3a; } QListWidget { background-color: #2e2e2e; } QLineEdit { background-color: #3a3a3a; color: #ffffff; }")
            self.dark_theme_applied = True
        else:
            # Revert to default theme
            self.setStyleSheet("")
            self.dark_theme_applied = False

    def blur_window(self, blur):
        effect = QGraphicsOpacityEffect(self.central_widget)
        effect.setOpacity(0.3 if blur else 1)
        self.central_widget.setGraphicsEffect(effect)


class AddPasswordPopup(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Add Password")
        self.setGeometry(150, 150, 300, 200)
        self.setModal(True)

        self.layout = QVBoxLayout(self)

        self.site_label = QLabel("Website/Application")
        self.site_input = QLineEdit()

        self.username_label = QLabel("Username/Email")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.eye_button = QPushButton("👁")
        self.eye_button.setCheckable(True)
        self.eye_button.toggled.connect(self.toggle_password_visibility)

        self.generate_button = QPushButton("Generate Password")
        self.generate_button.clicked.connect(self.generate_password)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_password)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.close)

        self.layout.addWidget(self.site_label)
        self.layout.addWidget(self.site_input)
        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.eye_button)
        self.layout.addWidget(self.generate_button)
        self.layout.addWidget(self.save_button)
        self.layout.addWidget(self.cancel_button)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def generate_password(self):
        password = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()") for i in range(16))
        self.password_input.setText(password)

    def save_password(self):
        site = self.site_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if site and username and password:
            passwords = self.parent.load_passwords()
            passwords.append({
                'site': site,
                'username': username,
                'password': password
            })
            self.parent.save_passwords(passwords)
            self.close()
        else:
            print("Please fill all fields")


class EditPasswordPopup(QDialog):
    def __init__(self, parent, entry):
        self.entry = entry  # Store the entry directly
        self.parent_manager = parent
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Edit Password")
        self.setGeometry(150, 150, 300, 200)
        self.setModal(True)

        self.layout = QVBoxLayout(self)

        self.site_label = QLabel("Website/Application")
        self.site_input = QLineEdit()
        self.site_input.setText(self.entry['site'])

        self.username_label = QLabel("Username/Email")
        self.username_input = QLineEdit()
        self.username_input.setText(self.entry['username'])

        self.password_label = QLabel("Password")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setText(self.entry['password'])

        self.eye_button = QPushButton("👁")
        self.eye_button.setCheckable(True)
        self.eye_button.toggled.connect(self.toggle_password_visibility)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_password)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.close)

        self.layout.addWidget(self.site_label)
        self.layout.addWidget(self.site_input)
        self.layout.addWidget(self.username_label)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.eye_button)
        self.layout.addWidget(self.save_button)
        self.layout.addWidget(self.cancel_button)

    def toggle_password_visibility(self, checked):
        if checked:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def save_password(self):
        site = self.site_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if site and username and password:
            passwords = self.parent_manager.load_passwords()  # Correctly reference the parent instance
            for entry in passwords:
                if entry == self.entry:
                    entry['site'] = site
                    entry['username'] = username
                    entry['password'] = password
                    break
            self.parent_manager.save_passwords(passwords)
            self.close()
        else:
            print("Please fill all fields")


class LoadingScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Loading")
        self.setGeometry(100, 100, 200, 100)
        
        self.layout = QVBoxLayout(self)

        self.loading_label = QLabel("Loading...")
        self.loading_label.setFont(QFont('Arial', 16))
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.loading_gif = QLabel(self)
        self.movie = QMovie("loading.gif")  #loading.gif file
        self.loading_gif.setMovie(self.movie)
        self.movie.start()

        self.layout.addWidget(self.loading_label)
        self.layout.addWidget(self.loading_gif)


def main():
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
