class User < ActiveRecord::Base
	before_save { self.email = email.downcase } # some DB adapters use case-sensitive indices, therefore we use this "callback" (a method that gets invoked at a particular point in the lifecycle of an Active Record object
	validates :name, presence: true, length: { maximum: 50 }
	validates :email, presence: true, length: { maximum: 255 }, format: { with: /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i },
		uniqueness: { case_sensitive: false }
	validates :password, presence: true, length: { minimum: 6 }
	has_secure_password
	# the method above gives:
	# - the ability to save a "password_digest" attribute to the database. This method hashes the password with bcrypt gem;
	# - a pair of virtual attributes ("password" and "password_confirmation"), including presence validations upon object creation and a validation requiring that they match;
	# - it adds to this model an "authenticate" method (user.authenticate('passwordInserted')) that returns the user when the password is correct (and false otherwise).
end