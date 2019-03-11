require 'securerandom'
require 'json'
require 'logger'
#require 'system'

$logger = Logger.new(STDOUT)

class ScanTimeOutError < StandardError

end

class SshScan
	attr_reader :raw_results
	attr_reader :results
	attr_reader :errored

	def initialize(config)
		@config = config
		@scanner_url = 'http://127.0.0.1:7331/scans'
		@errored = false
	end

	def start
		#@scan_id = start_scan
		$logger.info "Running scan for #{@config.ssh_scanner_target}"
		begin
			#wait_for_scan
			$logger.info "Retrieving scan results for #{@config.ssh_scanner_target}"
			#get_scan_report

			response = `ssh_scan -t #{@config.ssh_scanner_target}`
			@raw_results = JSON.parse(response)
			@results = @raw_results

		rescue ScanTimeOutError => err
			#$logger.warn "Scan #{@scan_id} timed out! Sending unfinished report to engine."
			get_scan_report(timed_out: true)
			@errored = true
		end

		$logger.info "Cleaning up scan report for #{@config.ssh_scanner_target}"
		#remove_scan
	end

	def start_scan
		begin
			response = `ssh_scan -t #{@config.ssh_scanner_target}`

			$logger.debug "Starting scan returned #{$?.success} code."

			id = JSON.parse(response)["id"]
			$logger.info "Started job with ID '#{id}'"
			id

		rescue => err
			$logger.warn err
			raise CamundaIncident.new("Failed to start SSH scan.", "This is most likely related to a error in the configuration. Check the SSH logs for more details.")
		end
	end

	def wait_for_scan
		last_request_count = 0
		last_request_count_change =Time.new

		loop do
			begin
				request = RestClient::Request.execute(
						method: :get,
						url: "#{@scanner_url}/#{@scan_id}",
						timeout: 2
				)
				$logger.debug "Status endpoint returned #{request.code}"
				response = JSON.parse(request)
				$logger.debug "Checking status of scan '#{@scan_id}': currently busy: #{response['busy']}"
			rescue => err
				$logger.warn err
			end

			findingCount = response["issues"].length
			currentRequestCount = response['statistics']['http']['request_count']
			$logger.info "Currently at #{findingCount} findings with #{currentRequestCount} requests made"

			if currentRequestCount == last_request_count
				if Time.now > last_request_count_change + (5 * 60)
					$logger.warn("Arachni request count hasn't updated in 5 min. It probably stuck...")
					raise ScanTimeOutError.new
				end
			else
				last_request_count = currentRequestCount
				last_request_count_change = Time.new
			end

			break unless response['busy']
			sleep 2
		end
	end

	def get_scan_report(timed_out: false)
		begin
			report = RestClient::Request.execute(
					method: :get,
					url: "#{@scanner_url}/#{@scan_id}/report.json",
					timeout: 2
			)
			@raw_results = JSON.parse(report)
			@results = @transformer.transform(@raw_results, timed_out: timed_out)
		rescue => err
			$logger.warn err
		end
	end

	def remove_scan
		begin
			$logger.debug "Deleting scan #{@scan_id}"
			RestClient::Request.execute(
					method: :delete,
					url: "#{@scanner_url}/#{@scan_id}",
					timeout: 2
			)
		rescue => err
			$logger.warn err
		end
	end
end
