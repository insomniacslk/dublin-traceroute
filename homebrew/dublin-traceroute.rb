class DublinTraceroute < Formula
  desc "NAT-aware multipath tracerouting tool"
  homepage "https://dublin-traceroute.net"
  url "https://github.com/insomniacslk/dublin-traceroute/archive/v0.4.2.tar.gz"
  sha256 "cae9b1a0a70f6b3dd566f680e7662efe65ee48d1c92198548d1a22b9ec76b58c"
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
