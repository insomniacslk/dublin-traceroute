class DublinTraceroute < Formula
  desc "NAT-aware multipath tracerouting tool"
  homepage "https://dublin-traceroute.net"
  url "https://github.com/insomniacslk/dublin-traceroute/archive/v0.3.3.tar.gz"
  sha256 "1359d65d030ae1bac269f43b97a727a6facab7f56eedf00bff480f5bc384082e"
  head "https://github.com/insomniacslk/dublin-traceroute.git"

  depends_on "cmake" => :build
  depends_on "libtins"
  depends_on "jsoncpp"

  def install
    system "cmake", ".", *std_cmake_args
    system "make", "install"
  end

  test do
    system "#{bin}/dublin-traceroute"
  end
end
