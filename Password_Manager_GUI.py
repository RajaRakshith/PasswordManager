#Import Modules

import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import *

from cryptography.fernet import Fernet
import os
import base64 # Used to convert binary to ASCII
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
from time import sleep
from random import randint
import xerox
import webbrowser

#Defining Variables:

conn = sqlite3.connect('Passwords.sqlite')
cursor = conn.cursor()

app=''
key=""

#Defining Functions
def get_key_from_pwd(pwd):
	global key
	global conn
	global cursor
	global temp_password
	pwd_bytes = pwd.encode()
	txt = open('salt.txt', 'rb')
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=txt.readlines()[0],
		iterations=100000,
		backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(pwd_bytes))
	#print(key)
	return key

def create_master_password(temp_password):
	salt = os.urandom(16)

	with open('salt.txt', 'wb') as txt:
		txt.write(salt)
		txt.close()

	print(temp_password)
	get_key_from_pwd(temp_password)

	first_line_db = 'SAMPLE_SAMPLEe'
	first_line_db_encoded = first_line_db.encode()
	fernet_key = Fernet(key)
	first_line_db_encrypted = fernet_key.encrypt(first_line_db_encoded)
	flded = first_line_db_encrypted.decode() #First line DB encrypted decoded

	cursor.execute('INSERT INTO Passwords (Name, Website, Username, Password) VALUES ("{}","{}","{}","{}")'.format(flded, flded, flded, flded))

	conn.commit()

	Window().show()
	#vault_locked()

class Window(QWidget):
	
	def __init__(self):
		super().__init__()

		self.setWindowTitle('Password Manager')
		self.setGeometry(100,100,650,400)
		self.setFixedSize(650,400)


		#PRE-DEFINING VARIABLES
		self.list_of_passwords_encrypted = []
		
		#function init_setup_pg1
		self.welcome_text_label = QLabel(self)
		self.details_text_label = QLabel(self)
		self.next_button = QPushButton(self)
		self.requirements_text_label_1 = QLabel(self)
		self.quit_button = QPushButton(self)

		#function init_setup_pg2
		self.requirements_text_label_1 = QLabel(self)
		self.requirements_text_label_2 = QLabel(self)
		self.requirements_text_label_3 = QLabel(self)
		self.requirements_text_label_4 = QLabel(self)
		self.requirements_header = QLabel(self)
		self.setup_enter_password_text = QLabel(self)
		self.setup_reenter_password_text = QLabel(self)
		self.passwords_dont_match = QLabel(self)
		self.setup_enter_password = QLineEdit(self)
		self.setup_reenter_password = QLineEdit(self)
		self.master_password_value = ''

		self.back_button = QPushButton(self)
		self.back_button.hide()

		self.setup_enter_password.hide()
		self.setup_reenter_password.hide()



		#function setup_password_changed
		self.meets_required_characters = False
		self.meets_uppercase_lowercase = False
		self.meets_number = False
		self.meets_symbol = False


		#Function vault_locked
		self.vault_locked_top_bold_text = QLabel(self)
		self.vault_locked_description = QLabel(self)
		self.vault_locked_enter_password_label = QLabel(self)

		self.vault_locked_password_field = QLineEdit(self)
		self.vault_locked_unlock_button = QPushButton(self)

		#Function main_password_manager_window
		self.add_password_button = QPushButton(self)
		self.add_password_button.hide()

		self.list_of_password_names_widget = QListWidget(self)
		self.list_of_password_names_widget.hide()

		#Function add_password
		self.item_name_label = QLabel(self)
		self.item_name_text_field = QLineEdit(self)
		self.website_name_label = QLabel(self)
		self.website_name_text_field = QLineEdit(self)
		self.username_name_label = QLabel(self)
		self.username_name_text_field = QLineEdit(self)
		self.password_name_label = QLabel(self)
		self.password_name_text_field = QLineEdit(self)
		self.generate_random_password_label = QLabel(self)
		self.generate_random_password_slider = QSlider(Qt.Horizontal, self)
		self.generate_random_password_slider_length = QLineEdit(self)

		self.add_password_save_item = QPushButton(self)
		self.add_password_cancel_button = QPushButton(self)

		self.random_password_generation = ''
		self.random_password_length = ''
		self.final_random_password_generation = ""
		self.iteration = 0
		self.loop = 0

		self.item_name_label.hide()
		self.item_name_text_field.hide()
		self.website_name_label.hide()
		self.website_name_text_field.hide()
		self.username_name_label.hide()
		self.username_name_text_field.hide()
		self.password_name_label.hide()
		self.password_name_text_field.hide()
		self.generate_random_password_label.hide()
		self.generate_random_password_slider.hide()
		self.generate_random_password_slider_length.hide()
		self.add_password_save_item.hide()
		self.add_password_cancel_button.hide()


		#Function password_list_clicked
		self.copy_password_button = QPushButton(self)
		self.copy_username_button = QPushButton(self)
		self.edit_item_button = QPushButton(self)
		self.delete_item_button = QPushButton(self)
		self.selected_item_encrypted = ''

		self.copy_password_button.hide()
		self.copy_username_button.hide()
		self.edit_item_button.hide()
		self.delete_item_button.hide()

		self.selected_item_decrypted = []

		#Function delete_item
		self.are_you_sure_delete_text = QLabel(self)
		self.are_you_sure_delete_text.setText('Are you sure you want to delete this password?')
		self.are_you_sure_yes_btn = QPushButton(self)
		self.are_you_sure_no_btn = QPushButton(self)

		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()


		self.username_text_field_password_clicked = QLineEdit(self)
		self.password_text_field_password_clicked = QLineEdit(self)

		self.username_text_field_password_clicked.hide()
		self.password_text_field_password_clicked.hide()

		self.username_label_password_clicked = QLabel(self)
		self.password_label_password_clicked = QLabel(self)

		self.launch_website_button_pwd_clicked = QPushButton(self)
		self.launch_website_button_pwd_clicked.hide()


		try:
			open('salt.txt')
			self.vault_locked()
		except FileNotFoundError:
			self.init_setup_pg1()



	def init_setup_pg1(self):
		self.requirements_text_label_1.hide()
		self.requirements_text_label_2.hide()
		self.requirements_text_label_3.hide()
		self.requirements_text_label_4.hide()
		self.requirements_header.hide()
		self.setup_enter_password_text.hide()
		self.setup_reenter_password_text.hide()
		self.setup_enter_password.hide()
		self.setup_reenter_password.hide()
		self.vault_locked_top_bold_text.hide()
		self.vault_locked_description.hide()
		self.vault_locked_enter_password_label.hide()
		self.vault_locked_password_field.hide()
		self.vault_locked_unlock_button.hide()
		self.are_you_sure_delete_text.hide()


		self.welcome_text_label.setText("Welcome to Password Manager")
		self.welcome_text_label.move(150,20)
		self.welcome_text_label.setStyleSheet('font:bold;font-size:16px;')

		self.details_text_label.setText("The next few pages will guide you through the steps necessary to complete the setup of your personal password vault.")
		self.details_text_label.move(150,55)
		self.details_text_label.setWordWrap(True)

		self.next_button.move(550,360)
		self.next_button.setText('Next ->')
		self.next_button.pressed.connect(self.init_setup_pg2)


		self.quit_button.move(480,360)
		self.quit_button.setText('Quit')
		self.quit_button.pressed.connect(sys.exit)

	def init_setup_pg2(self):
		self.requirements_text_label_1.show()
		self.requirements_text_label_2.show()
		self.requirements_text_label_3.show()
		self.requirements_text_label_4.show()
		self.requirements_header.show()
		self.setup_enter_password_text.show()
		self.setup_reenter_password_text.show()
		self.setup_enter_password.show()
		self.setup_reenter_password.hide()

		self.welcome_text_label.setText("Master Password Setup")
		self.details_text_label.setText("Set up a Master Password for you to unlock your password vault. The next button will be enabled once both the enter and the re-enter passwords match.")
		self.details_text_label.adjustSize()
		
		self.requirements_header.setText('Requirements:')
		self.requirements_header.move(150,115)
		self.requirements_header.setStyleSheet('font:bold')
		self.requirements_header.adjustSize()

		self.requirements_text_label_1.setText('At least 12 characters')
		self.requirements_text_label_1.move(150,140)
		self.requirements_text_label_1.adjustSize()
		self.requirements_text_label_1.setStyleSheet('color:red')

		self.requirements_text_label_2.setText('Uppercase and Lowercase letters')
		self.requirements_text_label_2.move(150,160)
		self.requirements_text_label_2.adjustSize()
		self.requirements_text_label_2.setStyleSheet('color:red')

		self.requirements_text_label_3.setText('At least 1 number')
		self.requirements_text_label_3.move(150,180)
		self.requirements_text_label_3.adjustSize()
		self.requirements_text_label_3.setStyleSheet('color:red')

		self.requirements_text_label_4.setText('At least 1 symbol')
		self.requirements_text_label_4.move(150,200)
		self.requirements_text_label_4.adjustSize()
		self.requirements_text_label_4.setStyleSheet('color:red')

		self.setup_enter_password_text.setText('Enter Password:')
		self.setup_enter_password_text.move(150,240)
		self.setup_enter_password_text.adjustSize()

		self.setup_enter_password.show()
		self.setup_enter_password.setGeometry(285,239,200,20)
		self.setup_enter_password.setEchoMode(QLineEdit.Password)
		self.setup_enter_password.textChanged.connect(self.setup_password_changed)

		self.setup_reenter_password_text.setText('Re-enter Password:')
		self.setup_reenter_password_text.move(150,265)
		self.setup_reenter_password_text.adjustSize()
		self.setup_reenter_password_text.hide()

		self.setup_reenter_password.setGeometry(285,264,200,20)
		self.setup_reenter_password.setEchoMode(QLineEdit.Password)

		self.back_button.show()
		self.back_button.setText('<- Back')
		self.back_button.move(475,360)
		self.back_button.pressed.connect(self.init_setup_pg1)

		self.passwords_dont_match.setText("The passwords don't match. Please try again.")
		self.passwords_dont_match.setStyleSheet('color:red;font-size:12px;')
		self.passwords_dont_match.move(285,290)
		self.passwords_dont_match.adjustSize()
		self.passwords_dont_match.hide()


		self.next_button.pressed.connect(self.password_match_check)
		self.quit_button.hide()


	def password_meets_all_requirements(self):
		if self.meets_number == True and self.meets_symbol == True and self.meets_uppercase_lowercase == True and self.meets_required_characters == True:
			return True
		else:
			return False

	def setup_password_changed(self):
		if len(self.setup_enter_password.text()) >= 12:
			self.meets_required_characters = True
			self.requirements_text_label_1.setStyleSheet('color:green')
		else:
			self.meets_required_characters = False
			self.requirements_text_label_1.setStyleSheet('color:red')
		if any(not char.isalnum() for char in self.setup_enter_password.text()) == True:
			self.meets_symbol = True
			self.requirements_text_label_4.setStyleSheet('color:green')
		else:
			self.meets_symbol = False
			self.requirements_text_label_4.setStyleSheet('color:red')
		if any(char.isdigit() for char in self.setup_enter_password.text()) == True:
			self.meets_number = True
			self.requirements_text_label_3.setStyleSheet('color:green')
		else:
			self.meets_number = False
			self.requirements_text_label_3.setStyleSheet('color:red')
		if self.setup_enter_password.text().islower() == False and self.setup_enter_password.text().isupper() == False and self.setup_enter_password.text() != '':
			self.meets_uppercase_lowercase = True
			self.requirements_text_label_2.setStyleSheet('color:green')
		else:
			self.meets_uppercase_lowercase = False
			self.requirements_text_label_2.setStyleSheet('color:red')

		if self.password_meets_all_requirements() == True:
			self.setup_reenter_password.show()
			self.setup_reenter_password_text.show()
		else:
			self.setup_reenter_password.hide()
			self.setup_reenter_password_text.hide()

	def password_match_check(self):
		if self.setup_enter_password.text() == self.setup_reenter_password.text() and self.password_meets_all_requirements() == True:
			self.master_password_value = self.setup_enter_password.text()
			self.init_setup_pg3()
		else:
			self.passwords_dont_match.show()
			self.setup_password_changed()

	def setup_finished_window_hide(self):
		create_master_password(self.master_password_value)
		Window.close(self)

	def init_setup_pg3(self):
		self.requirements_text_label_1.hide()
		self.requirements_text_label_2.hide()
		self.requirements_text_label_3.hide()
		self.requirements_text_label_4.hide()
		self.requirements_header.hide()
		self.setup_enter_password_text.hide()
		self.setup_reenter_password_text.hide()
		self.setup_enter_password.hide()
		self.setup_reenter_password.hide()
		self.back_button.hide()


		self.welcome_text_label.setText('Finish Setup')
		self.welcome_text_label.adjustSize()

		self.details_text_label.setText('Press Finish to finish setup of your personal password vault.  Restart the app to begin using the password manager. ')
		self.details_text_label.adjustSize()

		self.next_button.pressed.connect(self.setup_finished_window_hide)
		self.next_button.setText('Finish')
		self.next_button.setEnabled(False)
		self.next_button.setEnabled(True)
		self.next_button.setText('Finish')



	#Main Locked Window
	def vault_locked(self):
		self.welcome_text_label.hide()
		self.details_text_label.hide()
		self.next_button.hide()
		self.quit_button.hide()
		self.are_you_sure_delete_text.hide()

		self.vault_locked_top_bold_text.show()
		self.vault_locked_description.show()
		self.vault_locked_enter_password_label.show()
		self.vault_locked_password_field.show()
		self.vault_locked_unlock_button.show()

		self.vault_locked_top_bold_text.setText('Vault Locked')
		self.vault_locked_top_bold_text.setStyleSheet('font:bold;font-size:32px')
		self.vault_locked_top_bold_text.adjustSize()
		self.vault_locked_top_bold_text.move(225,40)

		self.vault_locked_description.setText('Your password vault is locked.  Unlock it by entering your master password below')
		self.vault_locked_description.setStyleSheet('font-size:16px')
		self.vault_locked_description.adjustSize()
		self.vault_locked_description.move(30,100)

		self.vault_locked_password_field.setGeometry(200,150,250,30)
		self.vault_locked_password_field.setEchoMode(QLineEdit.Password)
		self.vault_locked_password_field.returnPressed.connect(self.vault_password_check)

		self.vault_locked_unlock_button.setText('Unlock')
		self.vault_locked_unlock_button.setGeometry(268,200,100,40)
		self.vault_locked_unlock_button.setStyleSheet('background-color:lime;font:bold')
		self.vault_locked_unlock_button.pressed.connect(self.vault_password_check)

	def vault_password_check(self):
		self.password_entered = self.vault_locked_password_field.text()
		get_key_from_pwd(self.password_entered)
		self.fernet_key = Fernet(key)
		cursor.execute('SELECT * FROM Passwords')
		loop = 0
		for row in cursor:
			if loop == 0:
				verification_sample = row
				loop = loop + 1
			else:
				loop = loop + 1

		try:
			decrypt_sample = self.fernet_key.decrypt(verification_sample[0].encode())
			print(decrypt_sample)
			decrypted = True
			self.main_password_manager_window()
		except:
			#sleep(0.5)
			print('Password Incorrect. Please Try Again')
			
				
	def refresh_password_list(self):
		self.list_of_password_names_widget.clear()
		list_of_passwords_encrypted = []
		list_of_items_alphabetical = []
		cursor.execute('SELECT * FROM Passwords')
		loop = 0
		for item in cursor:
			if loop == 0:
				loop = loop + 1
			else:
				list_of_passwords_encrypted.append(item[0])
				self.list_of_passwords_encrypted.append(item[0])
		iteration = 0
		for item in list_of_passwords_encrypted:
			decrypted_item_encoded = self.fernet_key.decrypt(item.encode())
			decrypted_item_decoded = decrypted_item_encoded.decode()
			list_of_items_alphabetical.append(decrypted_item_decoded)

		list_of_items_alphabetical.sort()

		for item in list_of_items_alphabetical:
			self.list_of_password_names_widget.insertItem(iteration, item)
			iteration = iteration + 1
		self.list_of_password_names_widget.clicked.connect(self.password_list_clicked)


	def main_password_manager_window(self):
		self.vault_locked_top_bold_text.hide()
		self.vault_locked_description.hide()
		self.vault_locked_enter_password_label.hide()
		self.vault_locked_password_field.hide()
		self.vault_locked_unlock_button.hide()

		self.add_password_button.show()
		self.add_password_button.setText('Add Password')
		self.add_password_button.adjustSize()
		self.add_password_button.pressed.connect(self.add_password_button_pressed)
		
		self.list_of_password_names_widget.show()
		self.list_of_password_names_widget.setGeometry(30,35,350,360)
		
		self.refresh_password_list()

	def add_password_button_pressed(self):
		#print('hi')

		self.copy_username_button.hide()
		self.copy_password_button.hide()
		self.edit_item_button.hide()
		self.delete_item_button.hide()
		self.are_you_sure_delete_text.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()
		self.launch_website_button_pwd_clicked.hide()
		self.username_label_password_clicked.hide()
		self.username_text_field_password_clicked.hide()
		self.password_label_password_clicked.hide()
		self.password_text_field_password_clicked.hide()


		self.item_name_text_field.clear()
		self.website_name_text_field.clear()
		self.username_name_text_field.clear()
		self.password_name_text_field.clear()
		self.generate_random_password_slider_length.clear()

		self.item_name_label.show()
		self.item_name_label.setText('Name: ')
		self.item_name_label.move(400,30)
		self.item_name_label.adjustSize()		

		self.item_name_text_field.show()
		self.item_name_text_field.setGeometry(400,50,230,25)

		self.website_name_label.show()
		self.website_name_label.setText('Website:')
		self.website_name_label.move(400,80)
		self.website_name_label.adjustSize()

		self.website_name_text_field.show()
		self.website_name_text_field.setGeometry(400,100,230,25)

		self.username_name_label.show()
		self.username_name_label.setText('Username: ')
		self.username_name_label.move(400,130)
		self.username_name_label.adjustSize()

		self.username_name_text_field.show()
		self.username_name_text_field.setGeometry(400,150,230,25)

		self.password_name_label.show()
		self.password_name_label.setText('Password: ')
		self.password_name_label.move(400,180)
		self.password_name_label.adjustSize()

		self.password_name_text_field.show()
		self.password_name_text_field.setGeometry(400,200,230,25)
		#self.password_name_text_field.setEchoMode(QLineEdit.Password)

		self.generate_random_password_label.show()
		self.generate_random_password_label.setText('Generate Password: ')
		self.generate_random_password_label.move(400,250)
		self.generate_random_password_label.adjustSize()

		self.generate_random_password_slider.show()
		self.generate_random_password_slider.setGeometry(400,270,200,20)
		self.generate_random_password_slider.valueChanged[int].connect(self.random_password_slider_changed)

		self.generate_random_password_slider_length.show()
		self.generate_random_password_slider_length.setGeometry(610,270,30,30)
		self.generate_random_password_slider_length.textChanged.connect(self.random_password_length_changed)

		self.add_password_save_item.show()
		self.add_password_save_item.setText('Save')
		self.add_password_save_item.setGeometry(400,320,100,20)
		self.add_password_save_item.adjustSize()
		self.add_password_save_item.pressed.connect(self.new_item_save)

		self.add_password_cancel_button.show()
		self.add_password_cancel_button.setText('Cancel')
		self.add_password_cancel_button.setGeometry(500,320,100,20)
		self.add_password_cancel_button.adjustSize()
		self.add_password_cancel_button.pressed.connect(self.new_item_cancel)

	def random_password_slider_changed(self,value):
		self.generate_random_password_slider_length.setText(str(value))
		self.random_password_length = value
		self.generate_random_password(value)

	def random_password_length_changed(self,value):
		if value.isdigit() == True:
			#int(value)
			if int(value) >= 99:
				value = 99
				self.generate_random_password_slider_length.setText(str(value))
				self.generate_random_password_slider.setValue(int(value))
			elif int(value) < 0:
				value = 0
				self.generate_random_password_slider_length.setText(str(value))				
				self.generate_random_password_slider.setValue(int(value))
			else:
				self.generate_random_password_slider.setValue(int(value))
		else:
			self.generate_random_password_slider_length.setText('')
			self.generate_random_password_slider.setValue(int(0))

		self.generate_random_password(value)
		
	def generate_random_password(self,length):
		self.random_password_generation = ""
		self.final_random_password_generation = ''
		if len(str(self.random_password_length)) == 0:
			print()
		else:
			for x in range(1,int(self.random_password_length) + 1):
				random_number = randint(33,125)
				self.random_password_generation = self.random_password_generation + str(chr(random_number))
				self.final_random_password_generation = self.random_password_generation

			#print(self.final_random_password_generation)
			#print('\n\n\n\n\n')
			self.password_name_text_field.setText(self.final_random_password_generation)

	def new_item_save(self):
		item_name_send_db_decrypted = self.item_name_text_field.text()
		website_name_send_db_decrypted = self.website_name_text_field.text()
		username_name_send_db_decrypted = self.username_name_text_field.text()
		password_name_send_db_decrypted = self.password_name_text_field.text()

		if item_name_send_db_decrypted == '' or website_name_send_db_decrypted == '' or username_name_send_db_decrypted == '' or password_name_send_db_decrypted == '':
			print('You must fill out all fields before you can save.')
		elif item_name_send_db_decrypted == 'FXWxMK3pwh' and website_name_send_db_decrypted == 'BsqsmHKFJR' and username_name_send_db_decrypted == '3BfhfUgmUy' and password_name_send_db_decrypted == '4BFsHStdKc':
			pass

		else:
			encrypted_item_name = self.fernet_key.encrypt(item_name_send_db_decrypted.encode())
			encrypted_item_website = self.fernet_key.encrypt(website_name_send_db_decrypted.encode())
			encrypted_item_username = self.fernet_key.encrypt(username_name_send_db_decrypted.encode())
			encrypted_item_password = self.fernet_key.encrypt(password_name_send_db_decrypted.encode())
			"""
			print(self.fernet_key)
			print('')
			print(encrypted_item_name)
			"""
			cursor.execute('INSERT INTO Passwords (Name, Website, Username, Password) VALUES ("{}","{}","{}","{}")'.format(encrypted_item_name.decode(), encrypted_item_website.decode(), encrypted_item_username.decode(), encrypted_item_password.decode()))

			conn.commit()

			self.refresh_password_list()
			#print(self.list_of_passwords_encrypted)


			

			print('save ran')


			self.item_name_text_field.setText('FXWxMK3pwh')
			self.website_name_text_field.setText('BsqsmHKFJR')
			self.username_name_text_field.setText('3BfhfUgmUy')
			self.password_name_text_field.setText('4BFsHStdKc')
			self.generate_random_password_slider_length.clear()

			self.item_name_label.hide()
			self.item_name_text_field.hide()
			self.website_name_label.hide()
			self.website_name_text_field.hide()
			self.username_name_label.hide()
			self.username_name_text_field.hide()
			self.password_name_label.hide()
			self.password_name_text_field.hide()
			self.generate_random_password_label.hide()
			self.generate_random_password_slider.hide()
			self.generate_random_password_slider_length.hide()
			self.add_password_save_item.hide()
			self.add_password_cancel_button.hide()

	def new_item_cancel(self):
		self.item_name_label.hide()
		self.item_name_text_field.hide()
		self.website_name_label.hide()
		self.website_name_text_field.hide()
		self.username_name_label.hide()
		self.username_name_text_field.hide()
		self.password_name_label.hide()
		self.password_name_text_field.hide()
		self.generate_random_password_label.hide()
		self.generate_random_password_slider.hide()
		self.generate_random_password_slider_length.hide()
		self.add_password_save_item.hide()
		self.add_password_cancel_button.hide()

	def password_list_clicked(self):
		self.item_name_label.hide()
		self.item_name_text_field.hide()
		self.website_name_label.hide()
		self.website_name_text_field.hide()
		self.username_name_label.hide()
		self.username_name_text_field.hide()
		self.password_name_label.hide()
		self.password_name_text_field.hide()
		self.generate_random_password_label.hide()
		self.generate_random_password_slider.hide()
		self.generate_random_password_slider_length.hide()
		self.add_password_save_item.hide()
		self.add_password_cancel_button.hide()
		self.are_you_sure_delete_text.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()

		self.copy_username_button.show()
		self.copy_password_button.show()
		self.edit_item_button.show()
		self.delete_item_button.show()
		self.are_you_sure_delete_text.show()
		self.are_you_sure_yes_btn.show()
		self.are_you_sure_no_btn.show()
		self.launch_website_button_pwd_clicked.show()
		self.username_label_password_clicked.show()
		self.username_text_field_password_clicked.show()
		self.password_label_password_clicked.show()
		self.password_text_field_password_clicked.show()



		current_clicked_item_not_text = self.list_of_password_names_widget.currentItem()
		current_clicked_item = current_clicked_item_not_text.text()
		print(current_clicked_item)
		
		
		cursor.execute('SELECT * FROM Passwords')

		self.selected_item_encrypted = []
		for item in cursor:
			print(item)
			decrypted_sample = self.fernet_key.decrypt(item[0].encode()).decode()
			if decrypted_sample == current_clicked_item:
				self.selected_item_encrypted = item
			else:
				pass

		
		
		for item in self.selected_item_encrypted:
			print(item)
			self.selected_item_decrypted.append(self.fernet_key.decrypt(item.encode()).decode())
		print('')
		print(self.selected_item_decrypted)

		self.copy_username_button.setText('Copy Username')
		self.copy_username_button.setGeometry(440,30,150,30)
		self.copy_username_button.show()
		self.copy_username_button.pressed.connect(self.copy_username)

		self.copy_password_button.setText("Copy Password")
		self.copy_password_button.setGeometry(440,70,150,30)
		self.copy_password_button.show()
		self.copy_password_button.pressed.connect(self.copy_password)

		self.launch_website_button_pwd_clicked.setText('Launch Website')
		self.launch_website_button_pwd_clicked.setGeometry(440,110,150,30)
		self.launch_website_button_pwd_clicked.show()
		self.launch_website_button_pwd_clicked.pressed.connect(self.launch_website)

		self.edit_item_button.setText('Edit')
		self.edit_item_button.setGeometry(440,150,150,30)
		self.edit_item_button.show()
		self.edit_item_button.pressed.connect(self.edit_item)

		self.delete_item_button.setText('Delete')
		self.delete_item_button.setGeometry(440,190,150,30)
		self.delete_item_button.show()
		self.delete_item_button.setEnabled(False)
		self.delete_item_button.setEnabled(True)
		self.delete_item_button.pressed.connect(self.delete_item)


		self.username_label_password_clicked.setText('Username:')
		self.username_label_password_clicked.move(400,230)
		self.username_label_password_clicked.adjustSize()

		self.username_text_field_password_clicked.setText(self.selected_item_decrypted[2])
		self.username_text_field_password_clicked.setGeometry(400,260,200,50)
		self.username_text_field_password_clicked.setReadOnly(True)
		self.username_text_field_password_clicked.show()

		self.password_label_password_clicked.setText('Password:')
		self.password_label_password_clicked.move(400,320)
		self.password_label_password_clicked.adjustSize()


		self.password_text_field_password_clicked.setText(self.selected_item_decrypted[3])
		self.password_text_field_password_clicked.setGeometry(400,340,200,50)
		self.password_text_field_password_clicked.setReadOnly(True)
		self.password_text_field_password_clicked.show()

		"""
		for item in cursor:
			print(item)
	
"""


	def copy_username(self):
		print(self.selected_item_decrypted)
		xerox.copy(str(self.selected_item_decrypted[2]))
	def copy_password(self):
		xerox.copy(str(self.selected_item_decrypted[3]))

	def launch_website(self):
		website = self.selected_item_decrypted[1]
		if 'http' in website:
			webbrowser.open(website,new=2)
		else:
			webbrowser.open('http://' + website, new=2)

	def delete_item(self):
		self.delete_item_button.hide()
		self.are_you_sure_delete_text.show()
		self.are_you_sure_delete_text.move(381,180)
		self.are_you_sure_delete_text.adjustSize()
		self.are_you_sure_delete_text.setStyleSheet('font:12px')


		self.are_you_sure_yes_btn.setText('Yes')
		self.are_you_sure_yes_btn.move(435,200)
		self.are_you_sure_yes_btn.show()
		self.are_you_sure_yes_btn.setEnabled(False)
		self.are_you_sure_yes_btn.setEnabled(True)
		self.are_you_sure_yes_btn.pressed.connect(self.delete_yes_btn_fn)

		self.are_you_sure_no_btn.setText('No')
		self.are_you_sure_no_btn.move(535,200)
		self.are_you_sure_no_btn.show()
		self.are_you_sure_no_btn.setEnabled(False)
		self.are_you_sure_no_btn.setEnabled(True)
		self.are_you_sure_no_btn.pressed.connect(self.delete_no_btn_fn)

	def delete_yes_btn_fn(self):
		print(self.selected_item_encrypted)
		cursor.execute("DELETE FROM Passwords WHERE Name = '{}'".format(str(self.selected_item_encrypted[0])))
		conn.commit()

		self.copy_username_button.hide()
		self.copy_password_button.hide()
		self.edit_item_button.hide()
		self.delete_item_button.hide()
		self.are_you_sure_delete_text.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()
		self.launch_website_button_pwd_clicked.hide()
		self.username_label_password_clicked.hide()
		self.username_text_field_password_clicked.hide()
		self.password_label_password_clicked.hide()
		self.password_text_field_password_clicked.hide()

		self.refresh_password_list()

	def delete_no_btn_fn(self):
		self.are_you_sure_delete_text.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()
		self.delete_item_button.show()

	def edit_item(self):
		print(self.selected_item_decrypted)
		self.copy_username_button.hide()
		self.copy_password_button.hide()
		self.edit_item_button.hide()
		self.delete_item_button.hide()
		self.are_you_sure_delete_text.hide()
		self.are_you_sure_yes_btn.hide()
		self.are_you_sure_no_btn.hide()
		self.launch_website_button_pwd_clicked.hide()
		self.username_label_password_clicked.hide()
		self.username_text_field_password_clicked.hide()
		self.password_label_password_clicked.hide()
		self.password_text_field_password_clicked.hide()

		self.item_name_text_field.clear()
		self.website_name_text_field.clear()
		self.username_name_text_field.clear()
		self.password_name_text_field.clear()
		self.generate_random_password_slider_length.clear()

		self.item_name_label.show()
		self.item_name_label.setText('Name: ')
		self.item_name_label.move(400,30)
		self.item_name_label.adjustSize()		

		self.item_name_text_field.show()
		self.item_name_text_field.setGeometry(400,50,230,25)
		self.item_name_text_field.setText(self.selected_item_decrypted[0])

		self.website_name_label.show()
		self.website_name_label.setText('Website:')
		self.website_name_label.move(400,80)
		self.website_name_label.adjustSize()

		self.website_name_text_field.show()
		self.website_name_text_field.setGeometry(400,100,230,25)
		self.website_name_text_field.setText(self.selected_item_decrypted[1])

		self.username_name_label.show()
		self.username_name_label.setText('Username: ')
		self.username_name_label.move(400,130)
		self.username_name_label.adjustSize()

		self.username_name_text_field.show()
		self.username_name_text_field.setGeometry(400,150,230,25)
		self.username_name_text_field.setText(self.selected_item_decrypted[2])

		self.password_name_label.show()
		self.password_name_label.setText('Password: ')
		self.password_name_label.move(400,180)
		self.password_name_label.adjustSize()

		self.password_name_text_field.show()
		self.password_name_text_field.setGeometry(400,200,230,25)
		self.password_name_text_field.setText(self.selected_item_decrypted[3])
		#self.password_name_text_field.setEchoMode(QLineEdit.Password)

		self.generate_random_password_label.show()
		self.generate_random_password_label.setText('Generate Password: ')
		self.generate_random_password_label.move(400,250)
		self.generate_random_password_label.adjustSize()

		self.generate_random_password_slider.show()
		self.generate_random_password_slider.setGeometry(400,270,200,20)
		self.generate_random_password_slider.valueChanged[int].connect(self.random_password_slider_changed)

		self.generate_random_password_slider_length.show()
		self.generate_random_password_slider_length.setGeometry(610,270,30,30)
		self.generate_random_password_slider_length.textChanged.connect(self.random_password_length_changed)

		self.add_password_save_item.show()
		self.add_password_save_item.setText('Save')
		self.add_password_save_item.setGeometry(400,320,100,20)
		self.add_password_save_item.adjustSize()
		self.add_password_save_item.pressed.connect(self.existing_item_save)

		self.add_password_cancel_button.show()
		self.add_password_cancel_button.setText('Cancel')
		self.add_password_cancel_button.setGeometry(500,320,100,20)
		self.add_password_cancel_button.adjustSize()
		self.add_password_cancel_button.pressed.connect(self.existing_item_cancel)

	def existing_item_save(self):
		item_name_send_db_decrypted = self.item_name_text_field.text()
		website_name_send_db_decrypted = self.website_name_text_field.text()
		username_name_send_db_decrypted = self.username_name_text_field.text()
		password_name_send_db_decrypted = self.password_name_text_field.text()

		if item_name_send_db_decrypted == '' or website_name_send_db_decrypted == '' or username_name_send_db_decrypted == '' or password_name_send_db_decrypted == '':
			print('You must fill out all fields before you can save.')
		elif item_name_send_db_decrypted == 'FXWxMK3pwh' and website_name_send_db_decrypted == 'BsqsmHKFJR' and username_name_send_db_decrypted == '3BfhfUgmUy' and password_name_send_db_decrypted == '4BFsHStdKc':
			pass

		else:
			encrypted_item_name = self.fernet_key.encrypt(item_name_send_db_decrypted.encode())
			encrypted_item_website = self.fernet_key.encrypt(website_name_send_db_decrypted.encode())
			encrypted_item_username = self.fernet_key.encrypt(username_name_send_db_decrypted.encode())
			encrypted_item_password = self.fernet_key.encrypt(password_name_send_db_decrypted.encode())
			"""
			print(self.fernet_key)
			print('')
			print(encrypted_item_name)
			"""
			cursor.execute('INSERT INTO Passwords (Name, Website, Username, Password) VALUES ("{}","{}","{}","{}")'.format(encrypted_item_name.decode(), encrypted_item_website.decode(), encrypted_item_username.decode(), encrypted_item_password.decode()))

			conn.commit()

			self.refresh_password_list()
			#print(self.list_of_passwords_encrypted)


			

			print('save ran')


			self.item_name_text_field.setText('FXWxMK3pwh')
			self.website_name_text_field.setText('BsqsmHKFJR')
			self.username_name_text_field.setText('3BfhfUgmUy')
			self.password_name_text_field.setText('4BFsHStdKc')
			self.generate_random_password_slider_length.clear()

			self.item_name_label.hide()
			self.item_name_text_field.hide()
			self.website_name_label.hide()
			self.website_name_text_field.hide()
			self.username_name_label.hide()
			self.username_name_text_field.hide()
			self.password_name_label.hide()
			self.password_name_text_field.hide()
			self.generate_random_password_label.hide()
			self.generate_random_password_slider.hide()
			self.generate_random_password_slider_length.hide()
			self.add_password_save_item.hide()
			self.add_password_cancel_button.hide()

	def existing_item_cancel(self):
		self.password_list_clicked()

		



















#Starting the Program
try:
	open('salt.txt')
	app = QApplication(sys.argv)
	window = Window()
	window.show()
	sys.exit(app.exec_())
except FileNotFoundError:
	cursor.execute('DROP TABLE IF EXISTS Passwords')
	cursor.execute('CREATE TABLE "Passwords" ("Name" TEXT NOT NULL, "Website" TEXT NOT NULL, "Username" TEXT NOT NULL, "Password" TEXT NOT NULL)')

	conn.commit()

	#password = input("Please Enter a Master Password: ")
	app = QApplication(sys.argv)

	window = Window()
	window.show()
	sys.exit(app.exec_())

cursor.execute('SELECT * FROM Passwords')
loop = 0
for row in cursor:
	if loop == 0:
		verification_sample = row
		loop = loop + 1
	else:
		loop = loop + 1

decrypted = False
while decrypted == False:

	m_password_input = input('Enter Your Master Password: ')
	get_key_from_pwd(m_password_input)

	fernet_key = Fernet(key)
	try:
		decrypted_sample = fernet_key.decrypt(verification_sample[0].encode())
		decrypted = True
	except:
		sleep(0.5)
		print('Password Incorrect. Please Try Again')

exit = False
fernet_key = Fernet(key)
while exit == False:
	print("What would you like to do?\n\nView All Passwords - A\nView Password Based On Name - B\nAdd a Password - C\nDelete a Password - D\nExit - E\n")

	what_to_do_letter_value = input("Enter the Value Here: ")

	if what_to_do_letter_value == "A" or what_to_do_letter_value == "a":
		cursor.execute('SELECT * FROM Passwords')
		loop = 0
		for row in cursor:
			if loop == 0:
				loop = loop + 1
			else:
				fernet_key = Fernet(key)
				decrypted_name = fernet_key.decrypt(row[0].encode())
				decrypted_website = fernet_key.decrypt(row[1].encode())
				decrypted_username = fernet_key.decrypt(row[2].encode())
				decrypted_password = fernet_key.decrypt(row[3].encode())
				print(decrypted_name.decode() + "\t" + decrypted_website.decode() + "\t" + decrypted_username.decode() + "\t" + decrypted_password.decode())

		sleep(5)
		print("\n\n")

	elif what_to_do_letter_value == "B" or what_to_do_letter_value == "b":
		asked_name = input("Enter the Name: ")
		cursor.execute('SELECT * FROM Passwords')
		loop = 0
		for row in cursor:
			if loop == 0:
				loop = loop + 1
			else:
				fernet_key = Fernet(key)
				decrypted_name = fernet_key.decrypt(row[0].encode())
				decrypted_website = fernet_key.decrypt(row[1].encode())
				decrypted_username = fernet_key.decrypt(row[2].encode())
				decrypted_password = fernet_key.decrypt(row[3].encode())
				if decrypted_name.decode() == asked_name:
					print(decrypted_name.decode() + "\t" + decrypted_website.decode() + "\t" + decrypted_username.decode() + "\t" + decrypted_password.decode())
				else:
					continue
		sleep(5)
		print("\n\n")

	elif what_to_do_letter_value == "C" or what_to_do_letter_value == "c":
		asked_name = input("Name: ")
		asked_website = input("Website: ")
		asked_username = input("Username: ")
		asked_password = input("Password: ")

		fernet_key = Fernet(key)

		encrypted_name = fernet_key.encrypt(asked_name.encode())
		encrypted_website = fernet_key.encrypt(asked_website.encode())
		encrypted_username = fernet_key.encrypt(asked_username.encode())
		encrypted_password = fernet_key.encrypt(asked_password.encode())

		cursor.execute('INSERT INTO Passwords ("Name", "Website", "Username", "Password") VALUES ("{}","{}","{}","{}")'.format(encrypted_name.decode(), encrypted_website.decode(), encrypted_username.decode(), encrypted_password.decode()))

		conn.commit()

		sleep(2)
		print("\n\n")

	elif what_to_do_letter_value == "D" or what_to_do_letter_value == "d":
		asked_name = input("Enter the Name: ")
		cursor.execute('SELECT * FROM Passwords')
		loop = 0
		for row in cursor:
			if loop == 0:
				loop = loop + 1
			else:
				fernet_key = Fernet(key)
				decrypted_name = fernet_key.decrypt(row[0].encode())
				decrypted_website = fernet_key.decrypt(row[1].encode())
				decrypted_username = fernet_key.decrypt(row[2].encode())
				decrypted_password = fernet_key.decrypt(row[3].encode())

				if decrypted_name.decode() == asked_name:
					print(decrypted_name.decode() + "\t" + decrypted_website.decode() + "\t" + decrypted_username.decode() + "\t" + decrypted_password.decode())
					delete_prompt = input("Are you sure you would like to delete this? (y/n): ")
					if delete_prompt == "y" or delete_prompt == "Y":
						cursor.execute('DELETE FROM Passwords WHERE Name = "{}"'.format(row[0])) 
						#FIGURE OUT WHY WHEN DELETING IT DOES NOT DELETE
						conn.commit()
						print("delete successful")
				else:
					continue
		sleep(3)
		print("\n\n")

	elif what_to_do_letter_value == "E" or what_to_do_letter_value == "e":
		exit = True
		key = ''









