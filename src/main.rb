require 'sinatra'
require 'json'
require 'bundler'
Bundler.setup(:default)
require 'ruby-scanner-scaffolding'
require 'ruby-scanner-scaffolding/healthcheck'
require_relative './ssh_worker'

set :port, 8_080
set :bind, '0.0.0.0'
set :environment, :production

client =
  SshWorker.new(
    'http://localhost:8080',
    'ssh_webserverscan',
    %w[PROCESS_TARGETS]
  )

healthcheckClient = Healthcheck.new

get '/status' do
  status 500
  status 200 if client.healthy?
  content_type :json
  healthcheckClient.check(client)
end
