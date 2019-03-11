def is_set(val)
  if val != ''
  elsif val.is_a?(Array)
  val.length != 0
end
end

class SshConfiguration
  attr_accessor :job_id
  attr_accessor :ssh_scanner_target
  attr_accessor :ssh_scan_ports


  def self.from_target(job_id, target)
    config = SshConfiguration.new

    config.job_id = job_id
    config.ssh_scanner_target = target.dig('location')
    config.ssh_scan_ports = target.dig('attributes', 'SSH_SCAN_PORTS')

    config
  end
end
