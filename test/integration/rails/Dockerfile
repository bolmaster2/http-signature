# syntax = docker/dockerfile:1

FROM ruby:slim AS build

RUN apt-get update &&\
    apt-get install --yes build-essential git libyaml-dev pkg-config

RUN gem install rails
RUN rails new demo --minimal --skip-active-record --skip-git --skip-test

WORKDIR /demo
COPY . /src/http_signature
RUN ruby -0777 -pe 'gsub(/config\.assume_ssl\s*=.*\n/, "config.assume_ssl = false\n")' -i config/environments/production.rb &&\
    ruby -0777 -pe 'gsub(/config\.force_ssl\s*=.*\n/, "config.force_ssl = false\n")' -i config/environments/production.rb
RUN echo 'gem "http_signature", path: "/src/http_signature"' >> Gemfile &&\
    bundle config set --local disable_multisource true &&\
    bundle install

COPY <<-"EOF" config/routes.rb
Rails.application.routes.draw do
  root "rails/welcome#index"
  get "/protected", to: "protected#show"
end
EOF

RUN mkdir -p app/controllers config/initializers
COPY <<-"EOF" app/controllers/protected_controller.rb
require "http_signature/rails"

class ProtectedController < ApplicationController
  include HTTPSignature::Rails::Controller

  before_action :verify_http_signature!

  def show
    render json: {message: "Authenticated request"}
  end
end
EOF

COPY <<-"EOF" config/initializers/http_signature.rb
HTTPSignature.configure do |config|
  config.keys = [{id: "key-1", value: "MySecureKey"}]
end
EOF

FROM ruby:slim

RUN apt-get update &&\
    apt-get install --yes git

COPY --from=build /demo /demo
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /src/http_signature /src/http_signature

WORKDIR /demo
ENV RAILS_ENV=production
EXPOSE 3000
CMD ["bin/rails", "server"]

