def is_set(val)
  if val != ''
  elsif val.is_a?(Array)
  val.length != 0
end
end

class SshConfiguration
  attr_accessor :job_id
  attr_accessor :ssh_scanner_target


  def self.from_target(job_id, target)
    config = SshConfiguration.new

    config.job_id = job_id
    config.ssh_scanner_target = target.dig('location')

    config
  end
end
