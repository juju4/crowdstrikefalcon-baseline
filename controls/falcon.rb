# frozen_string_literal: true

# copyright:: 2022, The Authors
# license: All rights reserved

title 'Falcon section'

falcon_cid = input('falcon_cid', value: false, description: 'Check falcon use the correct Customer ID or CID')
falcon_tags = input('falcon_tags', value: false, description: 'Check falcon use appropriate tags, BU, product.')
falcon_proxy_host = input('falcon_proxy_host', value: false, description: 'Check falcon use appropriate proxy settings')
falcon_proxy_port = input('falcon_proxy_port', value: false, description: 'Check falcon use appropriate proxy settings')
falcon_build = input('falcon_build', value: '13207', description: 'Check falcon build is above or equal')
falcon_darwin_mdm_profile = input('falcon_darwin_mdm_profile', value: false, description: 'Check falcon has a MDM profile configured')

if os.darwin?
  falcon_dir = '/Applications/Falcon.app'
  falcond_bin = ''
  falconctl_bin = '/Applications/Falcon.app/Contents/Resources/falconctl'
  falcon_log = '/var/log/falcon-sensor.log'
else
  falcon_dir = '/opt/CrowdStrike'
  falcond_bin = '/opt/CrowdStrike/falcond'
  falconctl_bin = '/opt/CrowdStrike/falconctl'
  falcon_log = '/var/log/falcon-sensor.log'
  falcon_redhat_system_log = '/var/log/messages'
  falcon_debian_system_log = '/var/log/syslog'
end

control 'falcon-1.0' do
  impact 1.0
  title 'falcon should be present'
  desc 'Ensure falcon executables and configuration are present'
  only_if { os.family != 'windows' }

  if os.darwin?
    describe file('/Applications/Falcon.app/Contents/MacOS/Falcon') do
      it { should be_file }
      its('mode') { should cmp '0755' }
      it { should be_owned_by 'root' }
    end
  else
    describe file(falcon_dir.to_s) do
      it { should be_directory }
    end
    describe file(falcond_bin.to_s) do
      it { should be_symlink }
      it { should be_executable }
      it { should be_owned_by 'root' }
    end
    describe file(falconctl_bin.to_s) do
      it { should be_symlink }
      it { should be_executable }
      it { should be_owned_by 'root' }
    end
    describe file("#{falcon_dir}/falconstore") do
      it { should be_file }
      its('mode') { should cmp '0640' }
      it { should be_owned_by 'root' }
    end
    describe file("#{falcon_dir}/Registry.bin") do
      it { should be_file }
      its('mode') { should cmp '0640' }
      it { should be_owned_by 'root' }
    end
    if falcon_build
      describe command("sudo bash -c 'ls #{falcon_dir}/falcon-sensor?*' | sed 's#.*/falcon-sensor##'") do
        its('stdout') { should match falcon_build }
      end
    end
  end
end

control 'falcon-2.0' do
  impact 1.0
  title 'falcond should be running'
  desc 'Ensure falcond is running'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  if os.darwin?
    describe command('sudo systemextensionsctl list') do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match 'com.crowdstrike.falcon.Agent' }
    end
  else
    describe service('falcon-sensor') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
    describe processes('falcond') do
      its('users') { should eq %w(root) }
      its('entries.length') { should eq 1 }
    end
    describe processes('falcon-sensor') do
      its('users') { should eq %w(root) }
      its('entries.length') { should eq 1 }
    end
    # kernel modules won't be loaded if kernel is not supported. sensor in Reduced Functionality Mode (RFM)
    describe kernel_module('falcon_lsm_serviceable') do
      it { should be_loaded }
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
    describe kernel_module('falcon_nf_netcontain') do
      it { should be_loaded }
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
    describe kernel_module('falcon_kal') do
      it { should be_loaded }
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
    describe command('sudo /opt/CrowdStrike/falcon-kernel-check') do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should include ' is supported by Sensor version' }
      its('stdout') { should_not include ' is not supported by Sensor version' }
    end
  end
end

control 'falcon-3.0' do
  impact 1.0
  title 'falcon should be configured'
  desc 'Appropriate setting should be configured'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  if os.darwin?
    if falcon_darwin_mdm_profile
      describe command('profiles show') do
        its('stdout') { should_not match 'Error' }
        its('stderr') { should_not match 'Error' }
        its('stdout') { should match 'falcon' }
      end
    end
  else
    describe command("sudo #{falcon_dir}/falconctl -g --cid") do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match 'cid' }
    end
    if falcon_cid
      describe command("sudo #{falcon_dir}/falconctl -g --cid") do
        its('stdout') { should match falcon_cid }
      end
    end
    if falcon_tags
      describe command("sudo #{falcon_dir}/falconctl -g --tags") do
        its('stdout') { should match falcon_tags }
        its('stdout') { should_not match 'Sensor grouping tags are not set.' }
      end
    end
    if falcon_proxy_host && falcon_proxy_port
      describe command("sudo #{falcon_dir}/falconctl -g --apd") do
        its('stdout') { should_not match 'is not set.' }
      end
      describe command("sudo #{falcon_dir}/falconctl -g --aph") do
        its('stdout') { should_not match 'is not set.' }
        its('stdout') { should match falcon_proxy_host }
      end
      describe command("sudo #{falcon_dir}/falconctl -g --app") do
        its('stdout') { should_not match 'is not set.' }
        its('stdout') { should match falcon_proxy_port }
      end
    end
  end
end

control 'falcon-4.0' do
  impact 1.0
  title 'falcon should report to central console'
  desc 'An established network connection should exist'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  if os.darwin?
    describe command('sudo /Applications/Falcon.app/Contents/Resources/falconctl stats') do
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match /State: connected/ }
    end
  else
    describe command('sudo netstat -tap | grep falcon') do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should match %r{^tcp .* ec2-.*:https ESTABLISHED .*\/falcon-sensor} }
    end
  end
end

control 'falcon-5.0' do
  impact 1.0
  title 'falcon should be healthy'
  desc 'No error should appear'
  only_if { !(virtualization.role == 'guest' && virtualization.system == 'docker') && os.family != 'windows' }
  if os.darwin?
    describe command("log show --predicate 'process == \"com.crowdstrike.falcon.Agent\"' --last 20h | tail -10") do
      its('stdout') { should_not match 'Error' }
      its('stderr') { should_not match 'Error' }
      its('stdout') { should_not match 'Caller lacks TCC authorization for Full Disk Access' }
    end
  elsif os.redhat?
    describe file(falcon_redhat_system_log) do
      it { should be_file }
      its('content') { should_not match 'ProxyConnect: Could not connect to proxy' }
    end
    describe file(falcon_log) do
      it { should be_file }
      its('content') { should_not match 'ProxyConnect: Could not connect to proxy' }
    end
  elsif os.debian?
    describe file(falcon_debian_system_log) do
      it { should be_file }
      its('content') { should_not match 'ProxyConnect: Could not connect to proxy' }
    end
    describe file(falcon_log) do
      it { should be_file }
      its('content') { should_not match 'ProxyConnect: Could not connect to proxy' }
    end
  end
end
