class User < ApplicationRecord
  has_secure_password
  
  has_many :notes, dependent: :destroy
  
  validates :username, presence: true, uniqueness: true, 
            length: { minimum: 3, maximum: 50 },
            format: { with: /\A[a-zA-Z0-9_]+\z/, message: "can only contain letters, numbers, and underscores" }
  validates :password, presence: true, length: { minimum: 6 }, on: :create

  before_create :generate_uuid, if: :new_record?

  private

  def generate_uuid
    self.id = SecureRandom.uuid if id.blank?
  end
end