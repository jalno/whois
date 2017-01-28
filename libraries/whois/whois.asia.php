<?php
namespace packages\whois;
class asia_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        $r['regyinfo'] = array(
            'referrer' => 'http://www.dotasia.org/',
            'registrar' => 'DotAsia'
        );
        return $r;
    }

}
