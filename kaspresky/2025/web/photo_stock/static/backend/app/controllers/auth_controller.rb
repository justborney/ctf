class AuthController < ApplicationController
  skip_before_action :authenticate_user!, only: [:register, :login]
  
  def register
    user = User.new(user_params)
    
    if user.save
      token = JwtService.encode({ user_id: user.id, username: user.username })
      render json: {
        user: {
          id: user.id,
          username: user.username
        },
        token: token
      }, status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end
  
  def login
    user = User.find_by(username: params[:username])
    
    if user&.authenticate(params[:password])
      token = JwtService.encode({ user_id: user.id, username: user.username })
      render json: {
        user: {
          id: user.id,
          username: user.username
        },
        token: token
      }
    else
      render json: { error: 'Invalid username or password' }, status: :unauthorized
    end
  end
  
  def me
    render json: {
      user: {
        id: current_user.id,
        username: current_user.username
      }
    }
  end
  
  private
  
  def user_params
    params.require(:user).permit(:username, :password, :password_confirmation)
  end
end
