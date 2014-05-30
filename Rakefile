# -*- ruby -*-

require "rubygems"
gem 'hoe'
require "hoe"

Hoe.plugin :compiler
Hoe.plugin :minitest

Hoe.spec "otr" do
  developer("Marshall Lee", "hashtable@yandex.ru")

  license "MIT" # this should match the license in the README

  self.extra_rdoc_files = FileList['*.rdoc','ext/otr/*.c','ext/otr/*.h']
  self.spec_extras[:extensions] =  ["ext/otr/extconf.rb"]

  self.testlib = :minitest
end

# # vim: syntax=ruby
