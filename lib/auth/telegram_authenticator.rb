# frozen_string_literal: true

class TelegramAuthenticator < ::Auth::ManagedAuthenticator
  def name
    "telegram"
  end

  def enabled?
    SiteSetting.telegram_login_enabled
  end

  def register_middleware(omniauth)
    omniauth.provider :telegram,
                      setup: lambda { |env|
                        strategy = env["omniauth.strategy"]
                        strategy.options[:bot_name] = SiteSetting.telegram_login_bot_name
                        strategy.options[:bot_secret] = SiteSetting.telegram_login_bot_token
                      }
  end

  # def always_update_user_email?
  #   SiteSetting.login_with_telegram_overrides_email
  # end

  def primary_email_verified?(auth_token)
    true
  end
end
