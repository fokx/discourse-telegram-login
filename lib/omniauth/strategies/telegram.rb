require 'omniauth'
require 'openssl'
require 'base64'

module OmniAuth
  module Strategies
    class Telegram
      include OmniAuth::Strategy

      args [:bot_name, :bot_secret]

      option :name, 'telegram'
      option :bot_name, nil
      option :bot_secret, nil
      option :other_button_config, {}
      option :version, '22'

      REQUIRED_FIELDS = %w(id hash).freeze
      HASH_FIELDS = %w(auth_date first_name id last_name photo_url username).freeze

      def request_phase
        # TODO in the future, we can omit one button-clicking step
        # html << "<script>
        # const response = fetch('#{callback_url}?' + params, {
        #   method: 'POST',
        #   headers: {
        #     'X-Requested-With': 'XMLHttpRequest'
        #   },
        # });
        # this.popup = window.open('#{tg_auth_base_url}/auth?bot_id=#{bot_id}&origin=#{URI.encode_uri_component(full_host)}&embed=1&return_to=#{URI.encode_uri_component(callback_url)}', 'authWindow', )
        # </script>"
        # redirect "#{tg_auth_base_url}/auth?bot_id=#{bot_id}&origin=#{URI.encode_uri_component(full_host)}&embed=1&return_to=#{URI.encode_uri_component(callback_url)}"

        bot_id = options[:bot_secret].split(':')[0]
        tg_auth_base_url = "https://oauth.telegram.org"
        html = <<-HTML
          <!DOCTYPE html>
          <html>
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta name="viewport" content="width=device-width">
            <title>Login with Telegram</title>
            <style>
              html { color-scheme: light dark; }
            </style>
          </head>
          <body>
        HTML

        other_data_attrs = options.other_button_config.map { |k, v| "data-#{k}=\"#{v}\"" }.join(" ")

        html << "<script
              src=\"https://telegram.org/js/telegram-widget.js?#{options.version}\"
              data-telegram-login=\"#{options.bot_name}\"
              data-size=\"large\"
              data-userpic=\"false\"
              data-auth-url=\"#{callback_url}\"
        #{other_data_attrs}></script>"
        bot_id = options[:bot_secret].split(':')[0]

        html << "<script>
            window.Telegram.Login.auth(
              { bot_id: '#{bot_id}', request_access: true },
              (data) => {
                if (!data) {
                  console.log('authorization failed');
                } else {
                  console.log(data);
                  var params = Object.keys(data).map(function(k) {
                      return encodeURIComponent(k) + '=' + encodeURIComponent(data[k])
                  }).join('&');
                  console.log(params);
                  location.href = '#{callback_url}?' + params;
                }
              }
            );

        </script>"

        html << <<-HTML
          </body>
          </html>
        HTML

        Rack::Response.new(html, 200, 'content-type' => 'text/html').finish
      end

      def callback_phase
        if error = check_errors
          fail!(error)
        else
          super
        end
      end

      uid do
        request.params["id"]
      end

      info do
        {
          name: full_name(request.params["first_name"], request.params["last_name"]),
          nickname: request.params["username"],
          first_name: request.params["first_name"],
          last_name: request.params["last_name"],
          image: request.params["photo_url"],
          email: request.params["id"] + "@telegram.invalid"
        }
      end

      extra do
        {
          auth_date: Time.at(request.params["auth_date"].to_i)
        }
      end

      private

      def parse_tgAuthResult
        # TODO in the future, we can omit one button-clicking step
        # https://<XXX>/auth/telegram/callback#tgAuthResult=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        data = request.params["tgAuthResult"] # cannot capture URL fragment identifiers
        return false unless data
        a2 = data = Base64.urlsafe_encode64(data, padding: false)
        data = data.gsub(/-/, '+').gsub(/_/, '/')
        pad = data.length % 4
        if pad > 1
          data += '=' * (4 - pad)
        end
        a1 = JSON.parse(Base64.decode64(data))
        request.params = a2
        a2
      end

      def check_errors
        return :field_missing unless check_required_fields
        return :signature_mismatch unless check_signature
        return :session_expired unless check_session
      end

      def full_name(first_name, last_name)
        [first_name, last_name].compact.join(' ')
      end

      def check_required_fields
        REQUIRED_FIELDS.all? { |f| request.params.include?(f) }
      end

      def check_signature
        # https://core.telegram.org/widgets/login
        calculated_hash = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('SHA256'),
                                                  OpenSSL::Digest::SHA256.digest(options[:bot_secret]),
                                                  request.params.slice(*HASH_FIELDS)
                                                         .map { |k, v| "#{k}=#{v}" }
                                                         .sort
                                                         .join("\n")
        )
        request.params["hash"] == calculated_hash
      end

      def check_session
        Time.now.to_i - request.params["auth_date"].to_i <= 86400 # 24h
      end

    end
  end
end
