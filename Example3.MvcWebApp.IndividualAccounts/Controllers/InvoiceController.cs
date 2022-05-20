using System;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using AuthPermissions.AspNetCore;
using Example3.InvoiceCode.AppStart;
using Example3.InvoiceCode.Dtos;
using Example3.InvoiceCode.EfCoreClasses;
using Example3.InvoiceCode.EfCoreCode;
using Example3.InvoiceCode.Services;
using Example3.MvcWebApp.IndividualAccounts.PermissionsCode;
using Microsoft.EntityFrameworkCore;

namespace Example3.MvcWebApp.IndividualAccounts.Controllers
{
    public class InvoiceController : Controller
    {
        private readonly InvoicesDbContext _context;

        public InvoiceController(InvoicesDbContext context)
        {
            _context = context;
        }

        [HasPermission(Example3Permissions.InvoiceRead)]
        public async Task<IActionResult> Index(string message)
        {
            ViewBag.Message = message;

            // Get a IQueryable<Invoice> from the db and pass it to the InvoiceSummaryDto
            // that returns an IQueryable<InvoiceSummaryDto>
            var listInvoices = await InvoiceSummaryDto.SelectInvoices(_context.Invoices)
                .OrderByDescending(x => x.DateCreated)
                .ToListAsync();


            return View(listInvoices);
        }

        [HasPermission(Example3Permissions.InvoiceCreate)]
        public IActionResult CreateInvoice()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [HasPermission(Example3Permissions.InvoiceCreate)]
        public async Task<IActionResult> CreateInvoice(Invoice invoice)
        {
            // Create the Invoice Builder class
            var builder = new ExampleInvoiceBuilder(null);

            // Create a sample invoice.
            // Extract the tenant name from the user claims
            // Pass thru the InvoiceName parameter of the pass in Invoice
            var newInvoice = builder.CreateRandomInvoice(AddTenantNameClaim.GetTenantNameFromUser(User), invoice.InvoiceName);

            // Save the invoice to the db
            _context.Add(newInvoice);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index", new { message = $"Added the invoice '{newInvoice.InvoiceName}'." });
        }

    }
}
