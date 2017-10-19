class DublinTraceroute < Formula
  desc "NAT-aware multipath tracerouting tool"
  homepage "https://dublin-traceroute.net"
  url "https://github.com/insomniacslk/dublin-traceroute/archive/v0.4.2.tar.gz"
  sha256 "255980a630fb0d8b1cac270a656d6236bfddc5ba253bda4b898302918caf76d1"
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
