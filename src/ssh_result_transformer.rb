require 'securerandom'
require 'json'

class SshResultTransformer
  def initialize(uuid_provider = SecureRandom)
    @uuid_provider = uuid_provider
  end

  def transform(results, timed_out: false)
    findings = []

    results.each do |r|
      unless r.has_key? "error"
        location = (r.dig('hostname').empty?) ? r.dig('ip') : r.dig('hostname')
        hostname = (r.dig('hostname') unless r.dig('hostname').empty?)
        findings <<
            {
                id: @uuid_provider.uuid,
                name: 'SSH Service Information',
                description: '',
                category: 'SSH Service',
                osi_layer: 'NETWORK',
                severity: 'INFORMATIONAL',
                reference: {},
                hint: '',
                location: location,
                attributes: {
                    hostname: hostname,
                    ip_address: r.dig('ip'),
                    server_banner:
                        (r.dig('server_banner') unless r.dig('server_banner').empty?),
                    ssh_version: r.dig('ssh_version'),
                    os_cpe: r.dig('os_cpe'),
                    ssh_lib_cpe: r.dig('ssh_lib_cpe'),
                    compliance_policy: r.dig('compliance', 'policy'),
                    compliant: r.dig('compliance', 'compliant'),
                    grade: r.dig('compliance', 'grade'),
                    start_time: r.dig('start_time'),
                    end_time: r.dig('end_time'),
                    scan_duration_seconds: r.dig('scan_duration_seconds'),
                    references: r.dig('compliance', 'references'),
                    auth_methods: r.dig('auth_methods'),
                    key_algorithms: r.dig('key_algorithms'),
                    encryption_algorithms:
                        r.dig('encryption_algorithms_server_to_client'),
                    mac_algorithms: r.dig('mac_algorithms_server_to_client'),
                    compression_algorithms:
                        r.dig('compression_algorithms_server_to_client')
                }
            }

        unless r.dig('compliance', 'recommendations').nil?
          r.dig('compliance', 'recommendations')
              .each do |policy_violation_message|
            findings <<
                create_policy_violation_finding(
                    policy_violation_message,
                    location,
                    hostname,
                    r.dig('ip')
                )
          end
        end
      end
    end

    findings
  end

  def get_policy_violation_type(message)
    type = message.split(': ')[0]

    case type
    when /^Add these key exchange algorithms/
      {
        description: 'Good / encouraged SSH key algorithms are missing',
        name: 'Missing SSH Key Algorithms'
      }
    when /^Add these MAC algorithms/
      {
        description: 'Good / encouraged SSH MAC algorithms are missing',
        name: 'Missing SSH MAC Algorithms'
      }
    when /^Add these encryption ciphers/
      {
        description: 'Good / encouraged SSH encryption ciphers are missing',
        name: 'Missing SSH encryption Ciphers'
      }
    when /^Add these compression algorithms/
      {
        description: 'Good / encouraged SSH compression algorithms are missing',
        name: 'Missing SSH compression algorithms'
      }
    when /^Add these authentication methods/
      {
        description: 'Good / encouraged SSH authentication methods are missing',
        name: 'Missing SSH authentication methods'
      }
    when /^Remove these key exchange algorithms/
      {
        description: 'Deprecated / discouraged SSH key algorithms are used',
        name: 'Insecure SSH Key Algorithms'
      }
    when /^Remove these MAC algorithms/
      {
        description: 'Deprecated / discouraged SSH MAC algorithms are used',
        name: 'Insecure SSH MAC Algorithms'
      }
    when /^Remove these encryption ciphers/
      {
        description: 'Deprecated / discouraged SSH encryption ciphers are used',
        name: 'Insecure SSH encryption Ciphers'
      }
    when /^Remove these compression algorithms/
      {
        description:
          'Deprecated / discouraged SSH compression algorithms are used',
        name: 'Insecure SSH compression algorithms'
      }
    when /^Remove these authentication methods/
      {
        description: 'Discouraged SSH authentication methods are used',
        name: 'Discouraged SSH authentication methods'
      }
    when /^Update your ssh version to/
      {
        description: 'Outdated SSH protocol version used',
        name: 'Outdated SSH Protocol Version'
      }
    else
      raise Exception.new "Unexpected Policy Violation Type: '#{message}'"
    end
  end

  def create_policy_violation_finding(
    message, location, hostname, ip_address
  )
    policy_violation_type = get_policy_violation_type(message)

    payload = message.split(': ')[1].split(', ')

    {
      id: @uuid_provider.uuid,
      name: policy_violation_type[:name],
      description: policy_violation_type[:description],
      category: 'SSH Policy Violation',
      osi_layer: 'NETWORK',
      severity: 'MEDIUM',
      reference: {},
      hint: message,
      location: location,
      attributes: {
        hostname: hostname, ip_address: ip_address, payload: payload
      }
    }
  end
end
