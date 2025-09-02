class Note < ApplicationRecord
  belongs_to :user

  validates :title, presence: true, length: { maximum: 255 },
            format: { with: /\A[a-zA-Z0-9_]+\z/, message: "can only contain letters, numbers, and underscores" }
  validates :privacy, inclusion: { in: %w[private public], message: "must be 'private' or 'public'" }
  validates :image_data, presence: true, length: { maximum: 10.megabytes }

  before_create :generate_uuid, if: :new_record?

  def public?
    privacy == 'public'
  end

  def private?
    privacy == 'private'
  end

  def image_format
    return nil unless image_data
    if image_data.start_with?('data:image/png')
      'png'
    elsif image_data.start_with?('data:image/jpeg')
      'jpeg'
    else
      nil
    end
  end

  def save_image_to_file
    return unless image_data && image_format

    FileUtils.mkdir_p(Rails.root.join('storage', 'images'))

    filename = "#{id}.#{image_format}"
    filepath = Rails.root.join('storage', 'images', filename)

    base64_data = image_data.split(',')[1]
    return unless base64_data

    File.open(filepath, 'wb') do |file|
      file.write(Base64.decode64(base64_data))
    end

    update_column(:image_path, "storage/images/#{filename}")
  end

  def get_image_path
    return nil unless image_path
    Rails.root.join(image_path).to_s
  end

  def can_user_see_image?(user)
    return true if user && user.id == user_id
    return true if public?
    false
  end

  private

  def generate_uuid
    self.id = SecureRandom.uuid if id.blank?
  end
end
