<?php
namespace packages\whois;
class int_handler {

    function parse($data_str, $query) {
        $iana = new iana_handler();
        $r = array();
        $r['regrinfo'] = $iana->parse($data_str['rawdata'], $query);
        $r['regyinfo']['referrer'] = 'http://www.iana.org/int-dom/int.htm';
        $r['regyinfo']['registrar'] = 'Internet Assigned Numbers Authority';
        return $r;
    }

}
