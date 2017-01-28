<?php
namespace packages\whois;
class cat_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);

        if (!isset($r['regrinfo']['domain']['name']))
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo']['referrer'] = 'http://www.domini.cat/';
        $r['regyinfo']['registrar'] = 'Domini punt CAT';
        return $r;
    }

}
