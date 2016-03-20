class User < ActiveRecord::Base
  has_many :microposts, dependent: :destroy # destroying a user should also destroy their microposts
  has_many :active_relationships,   class_name:   "Relationship",
                                    foreign_key:  "follower_id",
                                    dependent:    :destroy
  has_many :following, through: :active_relationships, source: :followed
  has_many :passive_relationships,  class_name:   "Relationship",
                                    foreign_key:  "followed_id",
                                    dependent:    :destroy
  has_many :followers, through: :passive_relationships, source: :follower
  attr_accessor :remember_token, :activation_token, :reset_token
  before_create :create_activation_digest # User.new will make 2 new attributes for the object: activation_token and activation_digest(this one associated with a column in the DB, therefore will be written automatically when the user is saved)
  before_save { email.downcase! } # some DB adapters use case-sensitive indices, therefore we use this "callback" (a method that gets invoked at a particular point in the lifecycle of an Active Record object). before_save is automatically called before the object is saved (both creation and updates)
  validates :name, presence: true, length: { maximum: 50 }
  validates :email, presence: true, length: { maximum: 255 }, format: { with: /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i },
    uniqueness: { case_sensitive: false }
  validates :password, presence: true, length: { minimum: 6 }, allow_nil: true # has_secure_password includes a separate presence validation that specifically catches nil passwords
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
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  # Activates an account
  def activate
    #update_attribute(:activated,    true)
    #update_attribute(:activated_at, Time.zone.now)
    update_columns(activated: true, activated_at: Time.zone.now) # hits the DB once, instead of the above 2 separate transactions
  end

  # Sends activation email
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  # Sets the password reset attributes
  def create_reset_digest
    self.reset_token = User.new_token
    update_attribute(:reset_digest,  User.digest(reset_token))
    update_attribute(:reset_sent_at, Time.zone.now)
  end

  # Sends password reset email
  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end

  # Returns true if a password reset is expired
  def password_reset_expired?
    reset_sent_at < 2.hours.ago
  end

  # Defines a proto-feed
  #def feed
  #  Micropost.where("user_id = ?", id)
  #end

  # Follows a user
  def follow(other_user)
    active_relationships.create(followed_id: other_user.id)
  end

  # Unfollows a user
  def unfollow(other_user)
    active_relationships.find_by(followed_id: other_user.id).destroy
  end

  # Returns true if the current user is following other user
  def following?(other_user)
    following.include?(other_user)
  end

  # Returns a user's status feed
  def feed
    following_ids = "SELECT followed_id FROM relationships
                        WHERE  follower_id = :user_id"
    Micropost.where("user_id IN (#{following_ids})
                        OR user_id = :user_id", user_id: id)
  end

  private

  # Create the token and digest
  def create_activation_digest
    self.activation_token = User.new_token
    self.activation_digest = User.digest(activation_token)
  end

end
