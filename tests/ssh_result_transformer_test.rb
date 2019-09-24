require 'test/unit'
require 'json'
require_relative '../src/ssh_result_transformer'

class FakeUuidProvider
  def uuid
    '49bf7fd3-8512-4d73-a28f-608e493cd726'
  end
end

class SshResultTransformerTest < Test::Unit::TestCase

  def setup
    @transformer = SshResultTransformer.new(FakeUuidProvider.new)
  end

  def test_should_transform_a_empty_result_into_the_finding_format
    test_raw = <<EOM
[
  {
    "ssh_scan_version": "0.0.42",
    "ip": "127.0.0.1",
    "hostname": "",
    "port": 22,
    "server_banner": "",
    "ssh_version": "unknown",
    "os": "unknown",
    "os_cpe": "o:unknown",
    "ssh_lib": "unknown",
    "ssh_lib_cpe": "a:unknown",
    "key_algorithms": [

    ],
    "encryption_algorithms_client_to_server": [

    ],
    "encryption_algorithms_server_to_client": [

    ],
    "mac_algorithms_client_to_server": [

    ],
    "mac_algorithms_server_to_client": [

    ],
    "compression_algorithms_client_to_server": [

    ],
    "compression_algorithms_server_to_client": [

    ],
    "languages_client_to_server": [

    ],
    "languages_server_to_client": [

    ],
    "auth_methods": [

    ],
    "keys": null,
    "duplicate_host_key_ips": [

    ],
    "compliance": {
    },
    "start_time": "2019-03-20 14:54:36 +0100",
    "end_time": "2019-03-20 14:54:41 +0100",
    "scan_duration_seconds": 5.138688
  }
]
EOM
    result = JSON.parse(test_raw)

    assert_equal(
        @transformer.transform(result),
        [{
             id: '49bf7fd3-8512-4d73-a28f-608e493cd726',
             name: 'SSH Compliance',
             description: 'SSH Compliance Information',
             category: 'SSH Service',
             osi_layer: 'NETWORK',
             severity: 'INFORMATIONAL',
             reference: {},
             hint: '',
             location: '127.0.0.1',
             attributes: {
                 compliance_policy: nil,
                 compliant: nil,
                 hostname: nil,
                 os_cpe: 'o:unknown',
                 grade: nil,
                 start_time: '2019-03-20 14:54:36 +0100',
                 end_time: '2019-03-20 14:54:41 +0100',
                 scan_duration_seconds: 5.138688,
                 server_banner: nil,
                 ssh_lib_cpe: 'a:unknown',
                 ssh_version: 'unknown',
                 references: nil,
                 auth_methods: {}
             }
         }]
    )
  end

  def test_should_transform_proper_result_into_the_finding_format
    test_raw = <<EOM
[
  {
    "ssh_scan_version": "0.0.42",
    "ip": "138.201.126.99",
    "hostname": "securecodebox.io",
    "port": 22,
    "server_banner": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4",
    "ssh_version": 2.0,
    "os": "ubuntu",
    "os_cpe": "o:canonical:ubuntu:16.04",
    "ssh_lib": "openssh",
    "ssh_lib_cpe": "a:openssh:openssh:7.2p2",
    "key_algorithms": [
      "curve25519-sha256@libssh.org",
      "ecdh-sha2-nistp256",
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp521",
      "diffie-hellman-group-exchange-sha256",
      "diffie-hellman-group14-sha1"
    ],
    "encryption_algorithms_client_to_server": [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ],
    "encryption_algorithms_server_to_client": [
      "chacha20-poly1305@openssh.com",
      "aes128-ctr",
      "aes192-ctr",
      "aes256-ctr",
      "aes128-gcm@openssh.com",
      "aes256-gcm@openssh.com"
    ],
    "mac_algorithms_client_to_server": [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ],
    "mac_algorithms_server_to_client": [
      "umac-64-etm@openssh.com",
      "umac-128-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha1-etm@openssh.com",
      "umac-64@openssh.com",
      "umac-128@openssh.com",
      "hmac-sha2-256",
      "hmac-sha2-512",
      "hmac-sha1"
    ],
    "compression_algorithms_client_to_server": [
      "none",
      "zlib@openssh.com"
    ],
    "compression_algorithms_server_to_client": [
      "none",
      "zlib@openssh.com"
    ],
    "languages_client_to_server": [

    ],
    "languages_server_to_client": [

    ],
    "auth_methods": [
      "publickey"
    ],
    "keys": {
      "rsa": {
        "raw": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZsud3g6poObLpsD08cjCma1xwHbLsvUs1zjenKftQAt+NXOzgnEV6upmi3YZvQu67dUAWZtX0hS22gMCMIHbql6tbp/isJxLYtLUZLOiTm/vKQz3h/5y9h2oTyeAlA/4Xz4dA8g3RZvFHiQYN2HKvNtafn9hdQrUACZ/KYGbfr839cHeTaLi++lsUAdeeyb7x7WebktH81R3cz7dRhir2qaaqo/84/jR4s3b3koTtvdnFb0mSo2gQJP4QEACcw2w/U3HAhOsxs/Dh4pnJZBKI//HBQrc/ZIRRpfh4QAkX8hxFYGm450phf9Fp5oujjxzESfUw2LA1R2BHL9ZmzC+L",
        "length": 2048,
        "fingerprints": {
          "md5": "5f:cc:75:90:e9:6f:84:38:60:55:6f:9e:4a:a6:a7:b8",
          "sha1": "0d:4d:2e:0a:c0:c1:77:17:f4:c8:2f:4a:3c:e3:b6:3a:11:00:5e:d1",
          "sha256": "00:6e:ed:78:9b:be:13:0d:15:0e:84:8b:ba:fc:a1:b1:b0:1e:0b:35:12:15:dd:a6:8d:e6:34:f6:de:47:e5:8d"
        }
      },
      "ecdsa-sha2-nistp256": {
        "raw": "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBZyOh2ar1Ia36mRwV2ZEu87VnzR1hw0nO76hSaO0Rk507wXsyct5RCi3NJ1jNC9yXM7UllKaOX2q/MQGC+NHYw=",
        "length": 520,
        "fingerprints": {
          "md5": "1a:1c:3a:17:e4:a7:5a:85:6d:a5:68:66:07:f4:16:da",
          "sha1": "1b:0b:e7:c1:57:2b:a4:96:a2:1b:e9:8a:3d:8c:15:e2:87:27:00:bc",
          "sha256": "71:97:03:d3:2d:c9:e1:04:21:b3:bf:db:e0:f1:c3:6a:0e:50:c8:c9:6d:84:ac:22:25:4c:4b:44:7b:0f:38:e5"
        }
      },
      "ed25519": {
        "raw": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIACvhiz4GYkEi03nkB6jVXvcDMYFmjn6SoPCyHVK15QK",
        "length": 248,
        "fingerprints": {
          "md5": "ea:9e:55:79:99:40:2c:6b:30:d5:76:48:c8:36:45:32",
          "sha1": "7b:65:54:74:7e:0f:3f:02:c5:80:8c:49:33:32:41:a9:a6:6a:44:ba",
          "sha256": "a1:d6:80:82:33:4b:ff:3d:f9:6a:04:57:77:4a:b2:6f:32:d5:6c:d8:13:ba:9c:bf:bf:58:af:60:1b:75:d2:62"
        }
      }
    },
    "dns_keys": [

    ],
    "duplicate_host_key_ips": [

    ],
    "compliance": {
      "policy": "Mozilla Modern",
      "compliant": false,
      "recommendations": [
        "Remove these key exchange algorithms: diffie-hellman-group14-sha1",
        "Remove these MAC algorithms: umac-64-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, hmac-sha1"
      ],
      "references": [
        "https://wiki.mozilla.org/Security/Guidelines/OpenSSH"
      ],
      "grade": "C"
    },
    "start_time": "2019-09-23 17:47:50 +0200",
    "end_time": "2019-09-23 17:47:51 +0200",
    "scan_duration_seconds": 0.699356
  }
]
EOM
    result = JSON.parse(test_raw)

    findings = @transformer.transform(result)

    assert_equal(
        findings.first,
        {
            :attributes => {
                :compliance_policy => "Mozilla Modern",
                :compliant => false,
                :end_time => "2019-09-23 17:47:51 +0200",
                :grade => "C",
                :hostname => "securecodebox.io",
                :os_cpe => "o:canonical:ubuntu:16.04",
                :references => ["https://wiki.mozilla.org/Security/Guidelines/OpenSSH"],
                :scan_duration_seconds => 0.699356,
                :server_banner => "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4",
                :ssh_lib_cpe => "a:openssh:openssh:7.2p2",
                :ssh_version => 2.0,
                :start_time => "2019-09-23 17:47:50 +0200",
                :auth_methods => {
                    "publickey" => true
                }
            },
            :category => "SSH Service",
            :description => "SSH Compliance Information",
            :hint => "",
            :id => "49bf7fd3-8512-4d73-a28f-608e493cd726",
            :location => "138.201.126.99",
            :name => "SSH Compliance",
            :osi_layer => "NETWORK",
            :reference => {},
            :severity => "INFORMATIONAL"
        }
    )

    assert_equal(
      findings[1],
      {
          :attributes => {},
          :category => "SSH Service",
          :description => " diffie-hellman-group14-sha1",
          :hint => "",
          :id => "49bf7fd3-8512-4d73-a28f-608e493cd726",
          :location => "138.201.126.99",
          :name => "Remove these key exchange algorithms",
          :osi_layer => "NETWORK",
          :reference => {},
          :severity => "MEDIUM"
      }
    )

    assert_equal(
      findings[2],
        {
            :attributes => {},
            :category => "SSH Service",
            :description =>
                " umac-64-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, hmac-sha1",
            :hint => "",
            :id => "49bf7fd3-8512-4d73-a28f-608e493cd726",
            :location => "138.201.126.99",
            :name => "Remove these MAC algorithms",
            :osi_layer => "NETWORK",
            :reference => {},
            :severity => "MEDIUM"
        }
    )


  end
end