require 'securerandom'
require 'json'
require 'logger'
require 'pathname'

require_relative './ssh_result_transformer'

$logger = Logger.new(STDOUT)
$logger.level = if ENV.key? 'DEBUG' then Logger::DEBUG else Logger::INFO end

class SshScan
  attr_reader :raw_results
  attr_reader :results
  attr_reader :errored

  def initialize(targetfile, config)
    @targetfile = targetfile
    @config = config
    @errored = false
    @transformer = SshResultTransformer.new
  end

  def start
    $logger.info "Running scan for #{
                   File.basename(@targetfile, File.extname(@targetfile))
                 }"
    start_scan
    $logger.info "Retrieving scan results for #{
                   File.basename(@targetfile, File.extname(@targetfile))
                 }"
    get_scan_report
  end

  def start_scan
    resultsFile = File.open('/tmp/raw-results.txt', 'w+')

    sshCommandLine =
      "ssh_scan --fingerprint-db /tmp/fingerprint-db.yml -f #{
        Pathname.new(@targetfile)
      } -o #{Pathname.new(resultsFile)}"

    if not @config.ssh_policy_file.nil?
      sshCommandLine += "-P #{@config.filePath} "
    end
    if not @config.ssh_timeout_seconds.nil?
      sshCommandLine += "-T #{@config.ssh_timeout_seconds}"
    end
    resultsFile.write(`#{sshCommandLine}`)
    @raw_results = JSON.parse(resultsFile.read)
    File.delete(resultsFile)
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
