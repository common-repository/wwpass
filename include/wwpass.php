<?php
/**
 * wwpass.php
 *
 * WWPass Client Library, object style interface (php5 only) Version 2.0
 *
 * @copyright (c) WWPass Corporation, 2009-2012
 * @author Rostislav Kondratenko <r.kondratenko@wwpass.com>
 * @author Gregory Sitnin <g.sitnin@wwpass.com>
 * @author Vladimir Korshunov <v.korshunov@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

class WWPASSException extends Exception {}

final class WWPASSConnection {
    private $key_file;
    private $cert_file;
    private $ca_file;
    private $timeout;
    private $spfe_addr;
    
    const VERSION="2.0";
    
    public function __construct($key_file, $cert_file, $ca_file = false,$timeout=10, $spfe_addr='spfe.wwpass.com') {
        $this->key_file = $key_file;
        $this->cert_file = $cert_file;
        $this->ca_file = $ca_file;
        $this->timeout = $timeout;
        if (strpos($spfe_addr, '://') === false)
            $this->spfe_addr = 'https://'.$spfe_addr;
        else
            $this->spfe_addr = $spfe_addr;
    }
    
    private function makeGetParamsString(array $params) {
        $str = '';
        foreach ($params as $key=>$value) {
            $str .= urlencode($key).'='.urlencode($value).'&';
        }
        $str = substr($str, 0, -1);
        return $str;
    }
    
    private function makeRequest($method, $command, array $data, $attempts=3) {
        $command_url = $this->spfe_addr.'/'.$command.'.json';
        $SSL_VERIFYPEER = (bool) $this->ca_file;
        $curl_options = array(
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => $SSL_VERIFYPEER,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSLCERT => $this->cert_file,
            CURLOPT_SSLKEY => $this->key_file,
            CURLOPT_USERAGENT => 'WWPASS ClientLib for PHP/1.1',
            CURLOPT_VERBOSE => True,
        );
        if ($SSL_VERIFYPEER)
            $curl_options[CURLOPT_CAINFO] = $this->ca_file;
        switch(strtolower($method)) {
            case 'get':
                $curl_options[CURLOPT_HTTPGET] = true;
                $command_url .= '?'.$this->makeGetParamsString($data);
                break;
            case 'post':
                $curl_options[CURLOPT_POST] = true;
                $curl_options[CURLOPT_POSTFIELDS] = $this->makeGetParamsString($data);
                break;
        }
        $curl_options[CURLOPT_URL] = $command_url;
        $ch = curl_init();
        $res = false;
        for ($i=0; $i<$attempts; $i++) {
            if (!$res) {
                curl_setopt_array($ch, $curl_options);
                $answer = curl_exec($ch);
                if ($answer)
                    $res = $answer;
            }
        }
        $err = curl_error($ch);
        curl_close($ch);
        if (!$res)
            throw new WWPASSException('Cannot communicate to SPFE: '.$err);
        $result = json_decode($res);
        if ($result->encoding == 'base64')
            $result->data = base64_decode($result->data);
        if (!$result->result)
            throw new WWPASSException('SPFE returned error: '.$result->data);
        return $result->data;
    }
    
    public function getName() {
        $ticket = $this->getTicket(0);
        $pos = strpos($ticket,":");
        if ($pos === false)
            throw new WWPASSException('SPFE returned ticket without a colon.');
        return substr($ticket,0,$pos);
    }

    public function getTicket($ttl=120, $auth_types='') {
        return $this->makeRequest('GET', 'get', array('ttl'=>$ttl, 'auth_type'=>$auth_types));
    }

    public function putTicket($ticket, $ttl=120, $auth_types='') {
        return $this->makeRequest('GET', 'put', array('ticket'=>$ticket, 'ttl'=>$ttl, 'auth_type'=>$auth_types));
    }

    public function getPUID($ticket, $auth_types='', $finalize=false) {
        if ($finalize)
            return $this->makeRequest('GET', 'puid', array('ticket'=>$ticket, 'auth_type'=>$auth_types, 'finalize'=>1));
        else
            return $this->makeRequest('GET', 'puid', array('ticket'=>$ticket, 'auth_type'=>$auth_types));
    }

    public function readData($ticket, $container='', $finalize=false) {
        if ($finalize)
            return $this->makeRequest('GET', 'read', array('ticket'=>$ticket, 'container'=>$container, 'finalize'=>1));
        else
            return $this->makeRequest('GET', 'read', array('ticket'=>$ticket, 'container'=>$container));
    }

    public function readDataAndLock($ticket, $lock_timeout, $container='') {
        return $this->makeRequest('GET', 'read', array('ticket'=>$ticket, 'container'=>$container, 'to'=> $lock_timeout, 'lock'=>1));
    }

    public function writeData($ticket, $data, $container='', $finalize=false) {
        if ($finalize)
            return $this->makeRequest('POST', 'write', array('ticket'=>$ticket, 'data'=>$data, 'container'=>$container, 'finalize'=>1));
        else
            return $this->makeRequest('POST', 'write', array('ticket'=>$ticket, 'data'=>$data, 'container'=>$container));
    }

    public function writeDataAndUnlock($ticket, $data, $container='', $finalize=false) {
        if ($finalize)
            return $this->makeRequest('POST', 'write', array('ticket'=>$ticket, 'data'=>$data, 'container'=>$container, 'unlock'=>1, 'finalize'=>1));
        else
            return $this->makeRequest('POST', 'write', array('ticket'=>$ticket, 'data'=>$data, 'container'=>$container, 'unlock'=>1));
    }

    public function lock($ticket, $lock_timeout, $lockid='') {
        return $this->makeRequest('GET', 'lock', array('ticket'=>$ticket, 'to'=> $lock_timeout, 'lockid'=>$lockid));
    }

    public function unlock($ticket, $lockid='', $finalize=false) {
        if ($finalize)
            return $this->makeRequest('GET', 'unlock', array('ticket'=>$ticket, 'lockid'=>$lockid, 'finalize'=>1));
        else
            return $this->makeRequest('GET', 'unlock', array('ticket'=>$ticket, 'lockid'=>$lockid));
    }
    public function createPFID($data='') {
        if ($data)
            return $this->makeRequest('POST','sp/create', array('data'=>$data));
        else
            return $this->makeRequest('GET','sp/create', array('data'=>"")); # @todo fix documentstion
    }
    
    public function removePFID($pfid) {
        return $this->makeRequest('GET','sp/remove', array('pfid'=>$pfid));
    }
    public function readDataSP($pfid) {
        return $this->makeRequest('GET','sp/read', array('pfid'=>$pfid));
    }
    public function readDataSPandLock($pfid,$lock_timeout) {
        return $this->makeRequest('GET','sp/read', array('pfid'=>$pfid, 'to'=> $lock_timeout, 'lock'=>1));
    }
   
    public function writeDataSP($pfid, $data) {
        return $this->makeRequest('POST','sp/write', array('pfid'=>$pfid,'data'=>$data));
    }
    public function writeDataSPandUnlock($pfid, $data) {
        return $this->makeRequest('POST','sp/write', array('pfid'=>$pfid,'data'=>$data, 'lock'=>1));
    }
    
    public function lockSP($lockid,$lock_timeout) {
        return $this->makeRequest('GET', 'sp/lock', array('to'=> $lock_timeout, 'lockid'=>$lockid));
    }

    public function unlockSP($lockid) {
        return $this->makeRequest('GET', 'sp/unlock', array('lockid'=>$lockid));
    }
       
}

