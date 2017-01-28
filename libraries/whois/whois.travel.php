<?php
namespace packages\whois;
class travel_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo']['referrer'] = 'http://www.nic.travel/';
        $r['regyinfo']['registrar'] = 'Tralliance Corporation';
        return $r;
    }

}
