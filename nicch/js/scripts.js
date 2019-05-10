$(document).ready(function(){
    var maxField = 10; //Input fields increment limitation
    var addButton = $('.add_button'); //Add button selector
    var wrapper = $('.field_wrapper'); //Input field wrapper
    var fieldHTML = '<div class="form-group"><div class="col-xs-6"></div><div class="col-xs-3"><input type="text" class="form-control" name="ipaddress[]" placeholder="IPv4 or IPv6 address" /></div><div class="col-xs-1"><a href="javascript:void(0);" class="remove_button" title="Remove field"><img src="modules/registrars/nicch/img/remove-icon.png"/></a></div></div>'; //New input field html 
    var x = 1; //Initial field counter is 1


    $("#showCreateHost").click(function(){
        $("#createHost").show();
        $("#addHost").hide();
    });

    $("#cancelCreateHost").click(function(){
        $("#createHost").hide();
        $("#addHost").show();
    });

    $(addButton).click(function(){ //Once add button is clicked
        if(x < maxField){ //Check maximum number of input fields
            x++; //Increment field counter
            $(wrapper).append(fieldHTML); // Add field html
        }
    });
    $(wrapper).on('click', '.remove_button', function(e){ //Once remove button is clicked
        e.preventDefault();
        $(this).parent('div').parent('div').remove(); //Remove field html
        x--; //Decrement field counter
    });
});