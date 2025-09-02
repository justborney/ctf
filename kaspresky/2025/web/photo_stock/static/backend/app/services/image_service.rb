require 'mini_magick'

class ImageService
  def self.create_blurred_image(image_path)
    return nil unless File.exist?(image_path)

    blurred_path = image_path.gsub(/\.(\w+)$/, '_blurred.\1')

    begin
      image = MiniMagick::Image.open(image_path)
      image.blur('0x50')
      image.write(blurred_path)
      blurred_path
    rescue => e
      Rails.logger.error "Error creating blurred image: #{e.message}"
      nil
    end
  end
end
