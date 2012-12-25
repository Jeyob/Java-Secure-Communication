package Communication;

public class UDPdatagrampacket {

	private final long groupserial;
	private final int nr;
	
	private byte[] data = null;
	
	public UDPdatagrampacket(long groupserial, int nr, byte[] data){
			this.groupserial = groupserial;
			this.nr = nr;
			this.data = data;
		}
	
	public long getGroupserial(){
		return groupserial;
	}
	

	public int getNr(){ //returns the number of the package out of total count
		return nr;
	}

	public byte[] getData(){
		return data;
	}
}

