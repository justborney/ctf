class JwtService
  SECRET_KEY = 'super-secret-jwt-key'
  ALGORITHM = 'HS256'

  def self.encode(payload)
    payload[:exp] = 24.hours.from_now.to_i
    payload[:iat] = Time.current.to_i

    JWT.encode(payload, SECRET_KEY, ALGORITHM)
  end

  def self.decode(token)
    decoded = JWT.decode(token, SECRET_KEY, true, { algorithm: ALGORITHM })
    decoded[0]
  rescue JWT::DecodeError => e
    raise JWT::DecodeError, "Invalid token: #{e.message}"
  end

  def self.refresh_token(token)
    decoded = decode(token)
    user_id = decoded['user_id']

    token_iat = Time.at(decoded['iat'])
    if token_iat < 7.days.ago
      raise JWT::DecodeError, "Token too old to refresh"
    end

    encode({ user_id: user_id })
  end
end
