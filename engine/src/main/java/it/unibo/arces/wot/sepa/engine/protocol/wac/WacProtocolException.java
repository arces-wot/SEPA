/* SEPA exception on security
 * 
 * Author: Luca Roffia (luca.roffia@unibo.it)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package it.unibo.arces.wot.sepa.engine.protocol.wac;

public class WacProtocolException extends RuntimeException {

    /**
	 * 
	 */
	private static final long serialVersionUID = -1453391350370556374L;
	private final int code;
    private final String body;

    public WacProtocolException(int code, String body){
        this.code = code;
        this.body = body;
    }

    public int getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return body;
    }
}
