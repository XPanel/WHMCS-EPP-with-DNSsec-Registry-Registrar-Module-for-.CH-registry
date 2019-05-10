<?php
/**
*
* NOTICE OF LICENSE
*
*  @package   NICCH
*  @version   1.0.1
*  @author    Lilian Rudenco <info@xpanel.com>
*  @copyright 2019 Lilian Rudenco
*  @link      http://www.xpanel.com/
*  @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
*/

add_hook('ClientAreaHeadOutput', 1, function($vars) {
    $template = $vars['template'];
    return <<<HTML
<script type="text/javascript" src="modules/registrars/nicch/js/scripts.js"></script>
HTML;

});