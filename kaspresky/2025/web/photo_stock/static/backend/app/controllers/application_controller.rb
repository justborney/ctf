class ApplicationController < ActionController::API
  before_action :authenticate_user!

  private

  def authenticate_user!
    token = request.headers["Authorization"]&.split(" ")&.last
    
    if token.blank?
      render json: { error: "Authorization token required" }, status: :unauthorized
      return
    end

    begin
      @decoded_token = JwtService.decode(token)
      @current_user = User.find(@decoded_token["user_id"])
    rescue JWT::DecodeError => e
      render json: { error: "Invalid token: #{e.message}" }, status: :unauthorized
    rescue ActiveRecord::RecordNotFound
      render json: { error: "User not found" }, status: :unauthorized
    end
  end

  def current_user
    @current_user
  end
end
