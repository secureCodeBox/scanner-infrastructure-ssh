require 'json'

require_relative "../lib/camunda_worker"

require_relative "./ssh_scan"

class SshWorker < CamundaWorker
	attr_accessor :errored

	def initialize(camunda_url, topic, variables, task_lock_duration = 3600000, poll_interval = 5)
		super(camunda_url, topic, variables, task_lock_duration = 3600000, poll_interval = 5)

		@errored = false
	end

	def work(job_id, targets)
		configs = targets.map {|target|
			target.dig('location')
		}
		
		targetFile = File.open("/tmp/targets-of-#{job_id}.txt", "w+")
		targetFile.puts configs
		targetFile.close

		scan = SshScan.new(targetFile)
		scan.start
		if scan.errored
			@errored = true
		end
		scan

		{
				findings: scan.results,
				rawFindings: scan.raw_results.to_json,
				scannerId: @worker_id.to_s,
				scannerType: 'ssh'
		}
	end
end
