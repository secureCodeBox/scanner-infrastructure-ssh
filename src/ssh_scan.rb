require 'securerandom'
require 'json'
require 'logger'
require 'pathname'

require_relative './ssh_result_transformer'

$logger = Logger.new(STDOUT)

class ScanTimeOutError < StandardError

end

class SshScan
	attr_reader :raw_results
	attr_reader :results
	attr_reader :errored

	def initialize(config)
		@config = config
		@errored = false
		@transformer = SshResultTransformer.new
	end

	def start
		$logger.info "Running scan for #{File.basename(@config, File.extname(@config))}"
		begin
			start_scan
			$logger.info "Retrieving scan results for #{File.basename(@config, File.extname(@config))}"
			get_scan_report()
		rescue ScanTimeOutError => err
			$logger.warn "Scan timed out! Sending unfinished report to engine."
			get_scan_report(timed_out: true)
			@errored = true
		end
	end

	def start_scan
		begin
				@raw_results = JSON.parse(`ssh_scan -f #{Pathname.new(@config)}`)
		rescue => err
			$logger.warn err
			raise CamundaIncident.new("Failed to start SSH scan.", "This is most likely related to a error in the configuration. Check the SSH logs for more details.")
		end
	end

	def get_scan_report(timed_out: false)
		begin
			@results = @transformer.transform(@raw_results, timed_out: timed_out)
		rescue => err
			$logger.warn err
		end
	end
end
