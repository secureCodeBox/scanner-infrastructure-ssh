require 'json'
require 'ruby-scanner-scaffolding'
require 'pathname'

require_relative './ssh_configuration'

require_relative './ssh_scan'

class SshWorker < CamundaWorker
  attr_accessor :errored

  def initialize(
    camunda_url,
    topic,
    variables
  )
    super(
      camunda_url,
      topic,
      variables,
      3_600_000,
      5
    )

    @errored = false
  end

  def work(job_id, targets)
    locations = targets.map { |target| target.dig('location') }
    config = SshConfiguration.from_target(job_id, targets.first)

    target_file_path = Pathname.new "/tmp/targets-of-#{job_id}.txt"

    File.open(target_file_path, 'w+') do |target_file|
      target_file.puts locations
    end

    scan = SshScan.new(target_file_path, config)
    scan.start
    @errored = true if scan.errored

    File.delete target_file_path

    {
      findings: scan.results,
      rawFindings: scan.raw_results.to_json,
      scannerId: @worker_id.to_s,
      scannerType: 'ssh'
    }
  end
end
