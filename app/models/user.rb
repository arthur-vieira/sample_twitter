class User < ActiveRecord::Base
	attr_accessor :remember_token
	before_save { email.downcase! } # some DB adapters use case-sensitive indices, therefore we use this "callback" (a method that gets invoked at a particular point in the lifecycle of an Active Record object)
	validates :name, presence: true, length: { maximum: 50 }
	validates :email, presence: true, length: { maximum: 255 }, format: { with: /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i },
		uniqueness: { case_sensitive: false }
	validates :password, presence: true, length: { minimum: 6 }
	has_secure_password
	# the method above gives:
	# - the ability to save a "password_digest" attribute to the database. This method hashes the password with bcrypt gem;
	# - a pair of virtual (exist on the model object but aren't columns in the DB) attributes ("password" and "password_confirmation"), including presence validations upon object creation and a validation requiring that they match;
	# - it adds to this model an "authenticate" method (user.authenticate('passwordInserted')) that returns the user when the password is correct (and false otherwise).

	# Returns the hash digest of the given string
	def self.digest(string)
		cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
			BCrypt::Engine.cost
		BCrypt::Password.create(string, cost: cost)
	end

	# Returns a random token
	def self.new_token
		SecureRandom.urlsafe_base64
	end

	# Remembers a user in the database for use in persistent sessions
	def remember
		self.remember_token = User.new_token
		update_attribute(:remember_digest, User.digest(remember_token))
	end

	# Forgets a user (i.e. the opposite of the method "remember")
	def forget
		update_attribute(:remember_digest, nil)
	end

	# Returns true if the given token matches the digest
	def authenticated?(remember_token)
		return false if remember_digest.nil?
		BCrypt::Password.new(remember_digest).is_password?(remember_token)
	end
end
