<?php
namespace packages\whois;
class org_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);

        if (!strncmp($data_str['rawdata'][0], 'WHOIS LIMIT EXCEEDED', 20))
            $r['regrinfo']['registered'] = 'unknown';

        $r['regyinfo']['referrer'] = 'http://www.pir.org/';
        $r['regyinfo']['registrar'] = 'Public Interest Registry';
        return $r;
    }

}
