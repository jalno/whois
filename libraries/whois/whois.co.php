<?php
namespace packages\whois;
class co_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], array(), '-md--y');
        $r['regyinfo']['referrer'] = 'http://www.cointernet.com.co/';
        $r['regyinfo']['registrar'] = '.CO Internet, S.A.S.';
        return $r;
    }

}
