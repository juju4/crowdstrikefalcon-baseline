# frozen_string_literal: true

# copyright:: 2022, The Authors
# license: All rights reserved

title 'Falcon Windows section'

falcon_tags = input('falcon_tags', value: false, description: 'Check falcon use appropriate tags, BU, product.')

falcon_dir = 'C:\Windows\System32\drivers\CrowdStrike'
falcond_bin = 'C:\Program Files\CrowdStrike\CSFalconService.exe'

control 'falconwin-1.0' do
  impact 1.0
  title 'falcon should be present'
  desc 'Ensure falcon executables and configuration are present'
  only_if { os.family == 'windows' }

  describe file(falcon_dir) do
    it { should be_directory }
  end
  describe file("#{falcond_bin}") do
    it { should be_file }
  end
  describe registry_key({
    hive: 'HKEY_LOCAL_MACHINE',
    key: 'SOFTWARE\CrowdStrike\FWPolicy',
    }) do
    its('EnforcementLevel') { should eq 0 }
  end
end

control 'falconwin-2.0' do
  impact 1.0
  title 'falcond should be running'
  desc 'Ensure falcond is running'
  only_if { os.family == 'windows' }

  describe service('Base Filtering Engine') do
    it { should be_installed }
    it { should be_enabled }
  end
  describe service('DHCP Client') do
    it { should be_installed }
    it { should be_enabled }
  end
  describe service('DNS Client') do
    it { should be_installed }
    it { should be_enabled }
  end
  describe service('LMHosts') do
    it { should be_installed }
    it { should be_enabled }
  end
  describe service('CrowdStrike Falcon Sensor Service') do
    it { should be_installed }
    it { should be_enabled }
  end
end

control 'falconwin-3.0' do
  impact 1.0
  title 'falcon should be configured'
  desc 'Appropriate setting should be configured'
  only_if { os.family == 'windows' }

  if falcon_tags
    describe registry_key({
      hive: 'HKEY_LOCAL_MACHINE',
      key: 'SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default',
      }) do
      its('GroupingTags') { should eq falcon_tags }
    end
  end
end

control 'falconwin-4.0' do
  impact 1.0
  title 'falcon should report to central console'
  desc 'An established network connection should exist'
  only_if { os.family == 'windows' }

  describe command('netstat.exe -f') do
    its('stdout') { should_not match 'Error' }
    its('stderr') { should_not match 'Error' }
    its('stdout') { should match /TCP.*ec2-.*.us-west-1.compute.amazonaws.com:https  ESTABLISHED/ }
  end
end
