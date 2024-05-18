# frozen_string_literal: true

# name: discourse-telegram-login
# about: Enable Login via Telegram
# version: 1.0
# authors: fokx, Marco Sirabella
# url: https://github.com/fokx/discourse-telegram-login

enabled_site_setting :telegram_login_enabled

register_svg_icon "fab-telegram"

# extend_content_security_policy script_src: ['https://telegram.org/js/telegram-widget.js']

require_relative "lib/auth/telegram_authenticator"
require_relative "lib/omniauth/strategies/telegram"

auth_provider authenticator: ::TelegramAuthenticator.new, icon: "fab-telegram"
