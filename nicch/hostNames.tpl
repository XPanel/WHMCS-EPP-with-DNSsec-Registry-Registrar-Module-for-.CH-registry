<div class="alert alert-block alert-info">
    <p>{$LANG.domainname}: <strong>{$domain}</strong></p>
</div>

{if $error}
<div class="alert alert-error textcenter">
    {$error}
</div>
{else}
    {if $hosts eq 'YES'}
            <div class="form-group">
                <div class="col-xs-6"><b>Host</b></div>
                <div class="col-xs-4"><b>IP Addresses</b></div>
                <div class="col-xs-1"> </div>
            </div>
            <br />
            <hr>
        {foreach $hostList as $item}
            <form class="form-horizontal" role="form" method="post" action="clientarea.php" id="deleteHostForm">
            <input type="hidden" name="action" value="domaindetails" />
            <input type="hidden" name="id" value="{$domainid}" />
            <input type="hidden" name="modop" value="custom" />
            <input type="hidden" name="a" value="hostNames" />
            <input type="hidden" name="command" value="deleteHost" />
            <input type="hidden" name="host" value="{$item.host}" />

            <div class="form-group">
                <div class="col-xs-6">{$item.host}</div>
                <div class="col-xs-3">{foreach $item.ips as $ipI => $ip}{$ip.ip}<br />{/foreach}</div>
                <div class="col-xs-1"><input type="submit" class="btn btn-primary" value="Delete" /></div>
            </div>
            </form>
            <hr>
        {/foreach}
    {else}
        <p style="font-size: 100%; text-align: center; background: #EEE; padding: 5px">{$hosts}</p>
    {/if}
{/if}

<div id="addHost" class="form-group">
    <div class="col-xs-9"></div>
    <div class="col-xs-1"><button id="showCreateHost" class="btn btn-primary">Add</button></div>    
</div>

<br />

<div id="createHost" style="display: none;">
    <form class="form-horizontal" role="form" method="post" action="clientarea.php" id="createHostForm">
        <input type="hidden" name="action" value="domaindetails" />
        <input type="hidden" name="id" value="{$domainid}" />
        <input type="hidden" name="modop" value="custom" />
        <input type="hidden" name="a" value="hostNames" />
        <input type="hidden" name="command" value="createHost" />

        <div class="form-group">
            <div class="col-xs-3"><input type="text" class="form-control" name="host" placeholder="Hostname" /></div>
            <div class="col-xs-3">.{$domainname}</div>
            <div class="col-xs-3"><input type="text" class="form-control" name="ipaddress[]" placeholder="IPv4 or IPv6 address" /></div>
            <div class="col-xs-1"></div>
        </div>

        <div class="field_wrapper"></div>

        <div class="form-group">
            <div class="col-xs-6"></div>
            <div class="col-xs-4"><a href="javascript:void(0);" class="add_button" title="Add field">Add IP Address</a></div>
        </div>
    </form>
    <p class="text-center">
        <button type="submit" form="createHostForm" class="btn btn-primary">Create Host</button>
        <button id="cancelCreateHost" class="btn btn-primary">Cancel</button>
    </p>
</div>

<br />
