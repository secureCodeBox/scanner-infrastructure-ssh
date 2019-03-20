def is_set(val)
  if val != ''
  elsif val.is_a?(Array)
  val.length != 0
end
end

class SshConfiguration
  attr_accessor :job_id
  attr_accessor :ssh_policy_file
  attr_accessor :ssh_timeout_seconds


  def self.from_target(job_id, target)
    config = SshConfiguration.new

    config.job_id = job_id
    config.ssh_policy_file = target.dig('attributes','SSH_POLICY_FILE')
    config.ssh_timeout_seconds = target.dig('attributes','SSH_TIMEOUT_SECONDS')
    config
  end
end
