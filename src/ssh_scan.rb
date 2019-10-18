require 'securerandom'
require 'json'
require 'logger'
require 'pathname'
require 'ruby-scanner-scaffolding'

require_relative './ssh_result_transformer'

$logger = Logger.new(STDOUT)
$logger.level = if ENV.key? 'DEBUG' then Logger::DEBUG else Logger::INFO end

class SshScan
  attr_reader :raw_results
  attr_reader :results
  attr_reader :errored

  def initialize(target_file_path, config)
    @target_file_path = target_file_path
    @config = config
    @errored = false
    @transformer = SshResultTransformer.new
  end

  def start
    $logger.info "Running scan for #{@target_file_path.basename}"
    start_scan
    $logger.info "Retrieving scan results for #{@target_file_path.basename}"
    get_scan_report
  end

  def start_scan
      result_file_path = Pathname.new "/tmp/raw-results.txt"
      ssh_command_line = "ssh_scan --fingerprint-db /tmp/fingerprint-db.yml -f #{@target_file_path} -o #{result_file_path}"

      unless @config.ssh_policy_file.nil?
        ssh_command_line += "-P #{@config.filePath} "
      end
      unless @config.ssh_timeout_seconds.nil?
        ssh_command_line += "-T #{@config.ssh_timeout_seconds}"
      end

      # Execute the Scanner via command line
      `#{ssh_command_line}`

      File.open(result_file_path) do |results_file|
        @raw_results = JSON.parse(results_file.read)
        File.delete(results_file)
      end
  rescue => err
    $logger.warn err
    raise CamundaIncident.new(
            'Failed to start SSH scan.',
            'This is most likely related to a error in the configuration. Check the SSH logs for more details.'
          )
  end

  def get_scan_report
    @results = @transformer.transform(@raw_results)
  rescue => err
    $logger.warn err
  end
end
