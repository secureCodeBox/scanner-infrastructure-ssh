require 'json'
require 'ruby-scanner-scaffolding'

require_relative './ssh_configuration'

require_relative './ssh_scan'

class SshWorker < CamundaWorker
  attr_accessor :errored

  def initialize(
    camunda_url,
    topic,
    variables,
    task_lock_duration = 3_600_000,
    poll_interval = 5
  )
    super(
      camunda_url,
      topic,
      variables,
      task_lock_duration = 3_600_000,
      poll_interval = 5
    )

    @errored = false
  end

  def work(job_id, targets)
    locations = targets.map { |target| target.dig('location') }
    config = SshConfiguration.from_target(job_id, targets.first)

    targetFile = File.open("/tmp/targets-of-#{job_id}.txt", 'w+')
    targetFile.puts locations
    targetFile.close

    scan = SshScan.new(targetFile, config)
    scan.start
    @errored = true if scan.errored

    {
      findings: scan.results,
      rawFindings: scan.raw_results.to_json,
      scannerId: @worker_id.to_s,
      scannerType: 'ssh'
    }
  end
end
